import torch
print("hip:", torch.version.hip, "| gpu available:", torch.cuda.is_available())
x = torch.rand(2000, 2000, device="cuda")
print("matmul sum:", float((x @ x).sum()))