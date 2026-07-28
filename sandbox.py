"""The sandbox — protecting both sides (proposal section 08).

Every borrowed job runs inside a sandbox with hard caps on CPU, memory and wall
time, in a throwaway working directory, so a malicious or buggy workload cannot
touch the owner's files or run forever.

Two backends implement the same interface:

  * SubprocessSandbox — a resource-limited child process. Portable and needs no
    extra software. On POSIX it applies rlimits (CPU, address space, process
    count); everywhere it enforces a wall-clock timeout and, when psutil is
    present, an RSS watchdog. This is appropriate for the Phase 1 *trusted LAN*.
    It is NOT a hard security boundary.

  * DockerSandbox — `docker run` with `--network none`, `--memory`, `--cpus`
    and a read-only mount. A real isolation boundary when Docker is available.

Both expose:
    run(job, on_start=None) -> result dict   (blocking; call from a thread)
    cancel()                                  (thread-safe; used by instant reclaim)

The pluggable interface is deliberate: Phase 3 can drop in a hardened VM /
confidential-compute backend without touching the agent.
"""

import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import protocol as P

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


# interpreter name -> how to invoke a script file with it
def _interpreter_cmd(interpreter: str, script_path: str):
    if interpreter == "python":
        # -I: isolated mode (ignore env/user site); -u: unbuffered, so output streams
        return [sys.executable, "-I", "-u", script_path]
    if interpreter in ("bash", "sh"):
        return [interpreter, script_path]
    if interpreter == "node":
        return ["node", script_path]
    raise ValueError(f"unsupported interpreter: {interpreter!r}")


_SCRIPT_EXT = {"python": ".py", "bash": ".sh", "sh": ".sh", "node": ".js"}

# Max total size of output artifacts collected from a job (bytes).
ARTIFACT_CAP = 32 * 1024 * 1024


class _BaseSandbox:
    def __init__(self):
        self._lock = threading.Lock()
        self._cancelled = False

    def cancel(self):
        raise NotImplementedError

    def _write_script(self, workdir, workload):
        interpreter = workload["interpreter"]
        ext = _SCRIPT_EXT.get(interpreter, ".txt")
        path = os.path.join(workdir, "job" + ext)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(workload.get("script", ""))
        return path

    def _write_inputs(self, workdir, files):
        """Place the requester's base64 input files into the working directory
        (readable by the job). Path-traversal is prevented."""
        for name, b64 in (files or {}).items():
            dest = os.path.normpath(os.path.join(workdir, name))
            if not dest.startswith(os.path.abspath(workdir) + os.sep) and dest != workdir:
                continue  # reject '..' escapes
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                with open(dest, "wb") as f:
                    f.write(base64.b64decode(b64))
            except Exception:
                pass

    def _collect_artifacts(self, outdir, cap=ARTIFACT_CAP):
        """Read files the job wrote under `outdir` and return {relpath: base64},
        up to a total-size cap."""
        artifacts, total = {}, 0
        if not outdir or not os.path.isdir(outdir):
            return artifacts
        for root, _dirs, names in os.walk(outdir):
            for n in sorted(names):
                path = os.path.join(root, n)
                rel = os.path.relpath(path, outdir).replace(os.sep, "/")
                try:
                    data = open(path, "rb").read()
                except OSError:
                    continue
                if total + len(data) > cap:
                    artifacts["_truncated"] = base64.b64encode(
                        b"[artifacts exceeded size cap; some files omitted]").decode()
                    return artifacts
                total += len(data)
                artifacts[rel] = base64.b64encode(data).decode("ascii")
        return artifacts


class SubprocessSandbox(_BaseSandbox):
    def __init__(self):
        super().__init__()
        self._proc = None

    def _write_bootstrap(self, workdir):
        """A tiny launcher that adds the per-job deps dir to sys.path, then runs
        the user script as __main__. Lets us keep the interpreter in isolated
        (-I) mode while still importing the requester's installed packages."""
        path = os.path.join(workdir, "_bootstrap.py")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "import sys, runpy\n"
                "deps, script = sys.argv[1], sys.argv[2]\n"
                "sys.path.insert(0, deps)\n"
                "sys.argv = [script]\n"
                "runpy.run_path(script, run_name='__main__')\n"
            )
        return path

    def _install_deps(self, reqs, timeout, job_extra=None):
        """Install `reqs` into a per-node cache dir keyed by the requirement set,
        Python version and any custom index. Returns (deps_dir, None) on success,
        or (None, result_dict) on failure/cancel/timeout.

        `job_extra` are per-job pip args (e.g. --index-url for ROCm/CUDA wheels).
        The node owner can also steer pip globally without touching the protocol
        via env vars: AICN_PIP_CACHE and AICN_PIP_ARGS
        (e.g. AICN_PIP_ARGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org").
        """
        job_extra = job_extra or []
        cache_root = os.environ.get("AICN_PIP_CACHE") or \
            os.path.join(os.path.expanduser("~"), ".aicn", "pipcache")
        key_src = sys.version.split()[0] + "|" + json.dumps(sorted(reqs)) + "|" + json.dumps(job_extra)
        key = hashlib.sha256(key_src.encode()).hexdigest()[:16]
        target = os.path.join(cache_root, key)
        marker = os.path.join(target, ".aicn_complete")
        if os.path.exists(marker):
            return target, None  # cache hit — no reinstall

        os.makedirs(cache_root, exist_ok=True)
        tmp = target + ".tmp-" + uuid.uuid4().hex[:8]
        extra = shlex.split(os.environ.get("AICN_PIP_ARGS", "")) + list(job_extra)
        cmd = [sys.executable, "-m", "pip", "install", "--target", tmp,
               "--no-input", "--disable-pip-version-check",
               "--prefer-binary"] + extra + list(reqs)

        started = time.monotonic()
        with self._lock:
            if self._cancelled:
                return None, _result(P.CANCELLED, None, "", "cancelled before dependency install", 0.0)
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True)
        try:
            out, _ = self._proc.communicate(timeout=timeout)
            rc = self._proc.returncode
        except subprocess.TimeoutExpired:
            self._kill()
            self._drain()
            shutil.rmtree(tmp, ignore_errors=True)
            return None, _result(P.TIMEOUT, None, "",
                                 f"[sandbox] pip install exceeded {timeout}s", time.monotonic() - started)
        finally:
            with self._lock:
                self._proc = None

        if self._cancelled:
            shutil.rmtree(tmp, ignore_errors=True)
            return None, _result(P.CANCELLED, rc, "", "cancelled during dependency install",
                                 time.monotonic() - started)
        if rc != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return None, _result(P.ERROR, rc, "",
                                 "[sandbox] pip install failed:\n" + (out or ""), time.monotonic() - started)

        # Publish into the cache atomically-ish (single job per node in Phase 1).
        open(os.path.join(tmp, ".aicn_complete"), "w", encoding="utf-8").close()
        try:
            if os.path.exists(target):
                shutil.rmtree(target, ignore_errors=True)
            os.replace(tmp, target)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.exists(marker):
                return None, _result(P.ERROR, None, "",
                                     "[sandbox] failed to cache installed dependencies", 0.0)
        return target, None

    def _rlimits(self, max_runtime_sec):
        """Return a preexec_fn applying a generous CPU-time guard (POSIX only).

        Deliberately NOT set here:
          * RLIMIT_AS (address space) — GPU/CUDA and ML frameworks reserve huge
            *virtual* address space, so an AS cap makes them fail on init even
            when real memory use is tiny. Real memory is enforced by the RSS
            watchdog (`_start_mem_watchdog`) instead, which measures actual usage.
          * RLIMIT_NPROC — it counts *all* of the owner's processes, so on a busy
            server (Ollama, Kubernetes, ...) a low cap would break fork() for the
            job through no fault of its own.

        RLIMIT_CPU scales with core count so multi-threaded jobs aren't killed
        early; the wall-clock timeout remains the primary limit.
        """
        if os.name != "posix":
            return None

        import resource

        ncpu = os.cpu_count() or 1
        cpu_seconds = (int(max_runtime_sec) + 2) * ncpu  # allow all cores for the full run

        def apply():
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            except (ValueError, OSError):
                pass

        return apply

    def run(self, job, on_start=None, on_output=None):
        workload = job["workload"]
        max_runtime = job.get("max_runtime_sec", 60)
        ram_mb = (job.get("needs") or {}).get("ram_mb")
        stdin_data = workload.get("input", "") or ""

        workdir = tempfile.mkdtemp(prefix="aicn_job_")
        started = time.monotonic()
        oom_flag = {"hit": False}
        try:
            interpreter = workload["interpreter"]
            script_path = self._write_script(workdir, workload)
            self._write_inputs(workdir, workload.get("files"))   # input files -> workdir
            outdir = os.path.join(workdir, "out")                # job writes outputs here
            os.makedirs(outdir, exist_ok=True)
            ckptdir = os.path.join(workdir, "checkpoint")        # resume state lives here
            os.makedirs(ckptdir, exist_ok=True)
            self._write_inputs(ckptdir, job.get("checkpoint"))   # stage a prior checkpoint (resume)
            env = dict(os.environ)
            env["AICN_OUTPUT_DIR"] = outdir
            env["AICN_CHECKPOINT_DIR"] = ckptdir
            for k, v in (workload.get("env") or {}).items():   # per-job/task env (e.g. AICN_TASK)
                env[str(k)] = str(v)

            # Per-job dependencies: the requester brings the packages, so nodes
            # stay clean and any node can run any workload.
            pip_reqs = workload.get("pip") or []
            if pip_reqs and interpreter == "python":
                pip_extra = []
                if workload.get("pip_index_url"):
                    pip_extra += ["--index-url", workload["pip_index_url"]]
                if workload.get("pip_extra_index_url"):
                    pip_extra += ["--extra-index-url", workload["pip_extra_index_url"]]
                deps_dir, install_err = self._install_deps(
                    pip_reqs, workload.get("pip_timeout_sec", 600), pip_extra)
                if install_err is not None:
                    return install_err
                boot = self._write_bootstrap(workdir)
                cmd = [sys.executable, "-I", "-u", boot, deps_dir, script_path]
            else:
                cmd = _interpreter_cmd(interpreter, script_path)

            with self._lock:
                if self._cancelled:
                    return _result(P.CANCELLED, None, "", "cancelled before start", 0.0)
                self._proc = subprocess.Popen(
                    cmd,
                    cwd=workdir,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,                 # line-buffered for live streaming
                    env=env,
                    preexec_fn=self._rlimits(max_runtime),
                )
            if on_start:
                on_start()

            watchdog = self._start_mem_watchdog(ram_mb, oom_flag)
            try:
                stdout, stderr, exit_code, timed_out = _run_streaming(
                    self._proc, stdin_data, max_runtime, on_output, self._kill)
            finally:
                if watchdog:
                    watchdog.stop()

            runtime = time.monotonic() - started
            artifacts = self._collect_artifacts(outdir)    # files written to $AICN_OUTPUT_DIR
            checkpoint = self._collect_artifacts(ckptdir)  # resume state, preserved even if killed
            if timed_out:
                return _result(P.TIMEOUT, None, stdout,
                               stderr + f"\n[sandbox] killed after {max_runtime}s wall-clock limit",
                               runtime, artifacts, checkpoint)
            if oom_flag["hit"]:
                return _result(P.OOM, exit_code, stdout,
                               stderr + f"\n[sandbox] killed for exceeding {ram_mb} MB",
                               runtime, artifacts, checkpoint)
            with self._lock:
                if self._cancelled:
                    return _result(P.CANCELLED, exit_code, stdout, stderr, runtime, artifacts, checkpoint)
            status = P.OK if exit_code == 0 else P.ERROR
            return _result(status, exit_code, stdout, stderr, runtime, artifacts, checkpoint)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            with self._lock:
                self._proc = None

    def _start_mem_watchdog(self, ram_mb, oom_flag):
        if not ram_mb or psutil is None or self._proc is None:
            return None
        limit_bytes = int(ram_mb) * 1024 * 1024
        try:
            ps_proc = psutil.Process(self._proc.pid)
        except Exception:
            return None

        stop_evt = threading.Event()

        def watch():
            while not stop_evt.wait(0.5):
                try:
                    rss = ps_proc.memory_info().rss
                    for child in ps_proc.children(recursive=True):
                        try:
                            rss += child.memory_info().rss
                        except Exception:
                            pass
                    if rss > limit_bytes * 1.1:
                        oom_flag["hit"] = True
                        self._kill()
                        return
                except psutil.NoSuchProcess:
                    return
                except Exception:
                    return

        t = threading.Thread(target=watch, daemon=True)
        t.start()

        class _Handle:
            def stop(self_inner):
                stop_evt.set()

        return _Handle()

    def _drain(self):
        try:
            return self._proc.communicate(timeout=2)
        except Exception:
            return "", ""

    def _kill(self):
        proc = self._proc
        if proc is None:
            return
        try:
            if psutil is not None:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def cancel(self):
        with self._lock:
            self._cancelled = True
            self._kill()


def _container_interpreter_cmd(interpreter, script_path):
    """How to invoke a script *inside* the container (uses the image's own
    interpreter — NOT the host's sys.executable)."""
    if interpreter == "python":
        return ["python", "-I", "-u", script_path]
    if interpreter in ("bash", "sh"):
        return [interpreter, script_path]
    if interpreter == "node":
        return ["node", script_path]
    raise ValueError(f"unsupported interpreter: {interpreter!r}")


def _pump(pipe, stream_name, sink, on_output):
    """Read a child pipe line by line: accumulate into `sink` and stream each
    line to `on_output(stream_name, line)` as it arrives."""
    try:
        for line in iter(pipe.readline, ""):
            sink.append(line)
            if on_output:
                try:
                    on_output(stream_name, line)
                except Exception:
                    pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass


def _run_streaming(proc, stdin_data, timeout, on_output, kill):
    """Feed stdin, stream stdout/stderr live, enforce a wall-clock timeout.
    Returns (stdout, stderr, exit_code, timed_out)."""
    out_sink, err_sink = [], []
    if stdin_data:
        try:
            proc.stdin.write(stdin_data)
        except Exception:
            pass
    try:
        proc.stdin.close()
    except Exception:
        pass

    t_out = threading.Thread(target=_pump, args=(proc.stdout, "stdout", out_sink, on_output), daemon=True)
    t_err = threading.Thread(target=_pump, args=(proc.stderr, "stderr", err_sink, on_output), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    t_out.join(timeout=2)
    t_err.join(timeout=2)
    return "".join(out_sink), "".join(err_sink), proc.returncode, timed_out


def docker_available() -> bool:
    """True if a working Docker daemon is reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


class DockerSandbox(_BaseSandbox):
    """Hardened isolation via `docker run` — the backend for running untrusted,
    stranger-supplied code (Phase 3).

    The container is locked down: no network, all Linux capabilities dropped,
    no privilege escalation, a non-root user, a read-only root filesystem with
    only a size-capped tmpfs writable, a read-only mount of the job, and hard
    CPU/memory/PID/file-descriptor caps. Optionally runs under a stronger runtime
    (e.g. gVisor's `runsc`) for kernel-level syscall isolation.
    """

    IMAGES = {"python": "python:3-slim", "bash": "debian:stable-slim",
              "sh": "debian:stable-slim", "node": "node:slim"}

    def __init__(self, runtime=None, hardened=True):
        super().__init__()
        self._container = None
        self.runtime = runtime      # e.g. "runsc" (gVisor) or "kata-runtime"
        self.hardened = hardened

    def build_cmd(self, name, workdir, script_name, interpreter, needs, image,
                  outdir=None, ckptdir=None, env=None):
        """Construct the full `docker run ...` argv. Separated out so the
        hardening flags can be unit-tested without a Docker daemon."""
        ram_mb = needs.get("ram_mb")
        cpu = needs.get("cpu")
        cmd = ["docker", "run", "--rm", "--name", name,
               "--network", "none",                       # no network at all
               "--read-only",                             # immutable root fs
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",  # only scratch
               "-v", f"{workdir}:/job:ro",                # job mounted read-only
               "-w", "/tmp", "-i"]
        if outdir:
            # writable output volume the job can persist artifacts to
            cmd += ["-v", f"{outdir}:/out", "-e", "AICN_OUTPUT_DIR=/out"]
        if ckptdir:
            # writable checkpoint volume for resumable jobs
            cmd += ["-v", f"{ckptdir}:/checkpoint", "-e", "AICN_CHECKPOINT_DIR=/checkpoint"]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if self.hardened:
            cmd += ["--security-opt", "no-new-privileges",  # no setuid escalation
                    "--cap-drop", "ALL",                    # drop every capability
                    "--user", "65534:65534",                # run as nobody:nogroup
                    "--pids-limit", "256",                  # blunt fork bombs
                    "--ulimit", "nofile=256:512"]           # cap open files
        else:
            cmd += ["--pids-limit", "256"]
        if self.runtime:
            cmd += ["--runtime", self.runtime]
        if ram_mb:
            cmd += ["--memory", f"{int(ram_mb)}m", "--memory-swap", f"{int(ram_mb)}m"]
        if cpu:
            cmd += ["--cpus", str(cpu)]
        if needs.get("gpu"):
            # GPU passthrough necessarily relaxes isolation somewhat.
            if os.path.exists("/dev/kfd"):
                cmd += ["--device", "/dev/kfd", "--device", "/dev/dri", "--group-add", "video"]
            else:
                cmd += ["--gpus", "all"]
        cmd += [image]
        cmd += _container_interpreter_cmd(interpreter, "/job/" + script_name)
        return cmd

    def run(self, job, on_start=None, on_output=None):
        if not docker_available():
            return _result(P.ERROR, None, "",
                           "[sandbox] docker is required for the hardened sandbox but is "
                           "not available/running on this node", 0.0)

        workload = job["workload"]
        interpreter = workload["interpreter"]
        if workload.get("pip"):
            return _result(P.ERROR, None, "",
                           "[sandbox] per-job 'pip' is not available in the hardened sandbox "
                           "(runs with --network none). Bake dependencies into the image.", 0.0)
        max_runtime = job.get("max_runtime_sec", 60)
        needs = job.get("needs") or {}
        stdin_data = workload.get("input", "") or ""

        workdir = tempfile.mkdtemp(prefix="aicn_job_")
        outdir = tempfile.mkdtemp(prefix="aicn_out_")
        ckptdir = tempfile.mkdtemp(prefix="aicn_ckpt_")
        for d in (outdir, ckptdir):
            try:
                os.chmod(d, 0o777)   # so the non-root container user can write here
            except OSError:
                pass
        self._write_inputs(ckptdir, job.get("checkpoint"))   # stage a prior checkpoint (resume)
        name = "aicn_" + uuid.uuid4().hex[:12]
        started = time.monotonic()
        try:
            script_name = os.path.basename(self._write_script(workdir, workload))
            self._write_inputs(workdir, workload.get("files"))
            image = workload.get("image") or self.IMAGES.get(interpreter, "debian:stable-slim")
            cmd = self.build_cmd(name, workdir, script_name, interpreter, needs, image,
                                 outdir, ckptdir, workload.get("env"))

            with self._lock:
                if self._cancelled:
                    return _result(P.CANCELLED, None, "", "cancelled before start", 0.0)
                self._container = name
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, bufsize=1,
                )
            if on_start:
                on_start()

            def _kill():
                self._docker_kill(name)
                try:
                    proc.kill()
                except Exception:
                    pass

            stdout, stderr, exit_code, timed_out = _run_streaming(
                proc, stdin_data, max_runtime + 15, on_output, _kill)
            runtime = time.monotonic() - started
            artifacts = self._collect_artifacts(outdir)
            checkpoint = self._collect_artifacts(ckptdir)
            if timed_out:
                return _result(P.TIMEOUT, None, stdout,
                               stderr + f"\n[sandbox] killed after {max_runtime}s",
                               runtime, artifacts, checkpoint)
            with self._lock:
                if self._cancelled:
                    return _result(P.CANCELLED, exit_code, stdout, stderr, runtime, artifacts, checkpoint)
            if exit_code == 137:   # Docker's OOM-kill / SIGKILL
                return _result(P.OOM, exit_code, stdout,
                               stderr + "\n[sandbox] container killed (memory/limit)",
                               runtime, artifacts, checkpoint)
            status = P.OK if exit_code == 0 else P.ERROR
            return _result(status, exit_code, stdout, stderr, runtime, artifacts, checkpoint)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            shutil.rmtree(outdir, ignore_errors=True)
            shutil.rmtree(ckptdir, ignore_errors=True)
            with self._lock:
                self._container = None

    @staticmethod
    def _docker_kill(name):
        try:
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=10)
        except Exception:
            pass

    def cancel(self):
        with self._lock:
            self._cancelled = True
            if self._container:
                self._docker_kill(self._container)


def _result(status, exit_code, stdout, stderr, runtime_sec, artifacts=None, checkpoint=None):
    return {
        "status": status,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "runtime_sec": round(runtime_sec, 3),
        "artifacts": artifacts or {},
        "checkpoint": checkpoint or {},
    }


def make_sandbox(kind: str, runtime=None) -> _BaseSandbox:
    # "hardened" and "docker" both use the locked-down container profile; the
    # plain subprocess backend is for a trusted LAN only, NOT untrusted code.
    if kind in ("docker", "hardened"):
        return DockerSandbox(runtime=runtime, hardened=True)
    if kind == "subprocess":
        return SubprocessSandbox()
    raise ValueError(f"unknown sandbox backend: {kind!r}")
