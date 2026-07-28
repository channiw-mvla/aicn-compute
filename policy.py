"""Owner allow-rules (Phase 3).

A device owner decides what borrowed work their machine will actually run. This
policy is evaluated **on the node**, in the agent, before a job executes — it is
the owner's consent, enforced where the owner controls it. A job that violates
the policy is refused (the gateway then re-dispatches it to another node).

Configured under a "policy" block in the node config; every field is optional
and an empty policy allows everything (the default):

    "policy": {
      "interpreters": ["python"],          # allowed interpreters (empty = any)
      "allow_pip": false,                  # allow per-job pip installs
      "allow_gpu": true,                   # allow jobs that request a GPU
      "require_sandbox": "hardened",       # only run if the node uses this sandbox
      "max_ram_mb": 4096,                  # ceiling on requested RAM
      "max_runtime_sec": 600,              # ceiling on requested runtime
      "images": ["python:3-slim"],         # allowed container images (hardened; empty = any)
      "allow_requesters": ["<fingerprint>"],  # only these requesters (empty = any approved)
      "deny_requesters": ["<fingerprint>"]    # never these requesters
    }
"""


def _default_image(interpreter: str) -> str:
    from sandbox import DockerSandbox
    return DockerSandbox.IMAGES.get(interpreter, "debian:stable-slim")


class Policy:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    @property
    def active(self) -> bool:
        return bool(self.cfg)

    def check(self, job: dict, sandbox_kind: str, requester_fp: str = None):
        """Return (True, None) if the job may run, else (False, reason)."""
        w = job.get("workload", {}) or {}
        needs = job.get("needs", {}) or {}
        c = self.cfg
        interp = w.get("interpreter")

        allowed = c.get("interpreters")
        if allowed and interp not in allowed:
            return False, f"interpreter '{interp}' not allowed by owner policy"

        if w.get("pip") and not c.get("allow_pip", True):
            return False, "per-job pip installs are disabled by owner policy"

        if needs.get("gpu") and not c.get("allow_gpu", True):
            return False, "GPU jobs are disabled by owner policy"

        req_sb = c.get("require_sandbox")
        if req_sb:
            effective = "hardened" if sandbox_kind in ("hardened", "docker") else sandbox_kind
            want = "hardened" if req_sb in ("hardened", "docker") else req_sb
            if effective != want:
                return False, f"owner requires the '{req_sb}' sandbox (node is running '{sandbox_kind}')"

        max_ram = c.get("max_ram_mb")
        if max_ram and needs.get("ram_mb", 0) > max_ram:
            return False, f"requested RAM exceeds owner limit ({max_ram} MB)"

        max_rt = c.get("max_runtime_sec")
        if max_rt and job.get("max_runtime_sec", 0) > max_rt:
            return False, f"requested runtime exceeds owner limit ({max_rt}s)"

        images = c.get("images")
        if images:
            eff_image = w.get("image") or _default_image(interp)
            if eff_image not in images:
                return False, f"image '{eff_image}' not in owner allowlist"

        deny = c.get("deny_requesters") or []
        allow = c.get("allow_requesters") or []
        if requester_fp:
            if requester_fp in deny:
                return False, "requester denied by owner policy"
            if allow and requester_fp not in allow:
                return False, "requester not in owner allowlist"
        elif allow or deny:
            # policy names specific requesters but this job carries no identity
            return False, "owner policy requires an identified requester"

        return True, None
