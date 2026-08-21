"""GPU demo — proves the job really ran on the AMD card, then does real work.

Run it from the portal with:
    Environment : PyTorch + AI stack (AMD GPU)   [aicn-rocm:latest]
    Run on      : gpuserver-139
    Use GPU     : checked
    RAM         : 8192      (torch needs several GB — 512 will be killed)
    Max runtime : 300

Writes three files you can download from the job page: a trained model,
a benchmark summary, and a loss curve.
"""

import json
import os
import time

import torch

out = os.environ["AICN_OUTPUT_DIR"]
line = "=" * 52

# ── 1. which device are we actually on? ───────────────────────────────────
print(line)
print(f"torch {torch.__version__}   |   ROCm/HIP {torch.version.hip}")
on_gpu = torch.cuda.is_available()
print(f"GPU available : {on_gpu}")

dev = "cuda" if on_gpu else "cpu"
gpu_name = "CPU only"
if on_gpu:
    props = torch.cuda.get_device_properties(0)
    gpu_name = props.name
    print(f"device        : {props.name}")
    print(f"VRAM          : {props.total_memory / 1e9:.1f} GB")
print(line)

# ── 2. how fast is it? ────────────────────────────────────────────────────
N, ITERS = 4096, 20
a = torch.randn(N, N, device=dev)
b = torch.randn(N, N, device=dev)

for _ in range(3):                       # warm-up (first call compiles kernels)
    a @ b
if on_gpu:
    torch.cuda.synchronize()

t0 = time.time()
for _ in range(ITERS):
    c = a @ b
if on_gpu:
    torch.cuda.synchronize()
elapsed = time.time() - t0

tflops = (2 * N ** 3 * ITERS) / elapsed / 1e12
print(f"matmul {N}x{N} x{ITERS}  ->  {elapsed:.2f}s   {tflops:.1f} TFLOP/s")
print(line)

# ── 3. train something, so it isn't just a benchmark ──────────────────────
torch.manual_seed(0)
X = torch.randn(20_000, 64, device=dev)
true_w = torch.randn(64, 1, device=dev)
y = X @ true_w + 0.1 * torch.randn(20_000, 1, device=dev)

model = torch.nn.Sequential(
    torch.nn.Linear(64, 256), torch.nn.ReLU(),
    torch.nn.Linear(256, 128), torch.nn.ReLU(),
    torch.nn.Linear(128, 1),
).to(dev)

opt = torch.optim.Adam(model.parameters(), lr=1e-3)
loss_fn = torch.nn.MSELoss()

history = []
EPOCHS = 200
t0 = time.time()
for epoch in range(1, EPOCHS + 1):
    opt.zero_grad()
    loss = loss_fn(model(X), y)
    loss.backward()
    opt.step()
    history.append(float(loss))
    if epoch == 1 or epoch % 40 == 0:
        print(f"epoch {epoch:>4}   loss {float(loss):.4f}")
train_time = time.time() - t0

print(line)
print(f"trained {EPOCHS} epochs on {gpu_name} in {train_time:.1f}s")
print(f"loss {history[0]:.3f}  ->  {history[-1]:.4f}")
print(line)

# ── 4. save the results so they come back as downloadable files ───────────
torch.save(model.state_dict(), os.path.join(out, "model.pt"))

with open(os.path.join(out, "benchmark.json"), "w") as f:
    json.dump({
        "device": gpu_name,
        "gpu_available": on_gpu,
        "torch": torch.__version__,
        "hip": torch.version.hip,
        "matmul_tflops": round(tflops, 2),
        "train_seconds": round(train_time, 2),
        "loss_start": round(history[0], 4),
        "loss_final": round(history[-1], 6),
    }, f, indent=2)

import matplotlib                        # noqa: E402  (headless backend must be set first)
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402

plt.figure(figsize=(7, 4))
plt.plot(history, linewidth=2)
plt.yscale("log")
plt.title(f"Training loss — {gpu_name}")
plt.xlabel("epoch")
plt.ylabel("MSE loss (log scale)")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(out, "training_loss.png"), dpi=130)

print("saved:", ", ".join(sorted(os.listdir(out))))
