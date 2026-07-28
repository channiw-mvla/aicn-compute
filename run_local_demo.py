"""End-to-end Phase 1 demo on localhost (proposal roadmap: "prove a job runs
end to end on a LAN").

Starts a gateway and one always-available node agent as subprocesses, then
submits the example job through the requester client and prints the result.
Everything binds to 127.0.0.1, so nothing is exposed to the network.

    python run_local_demo.py
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
PORT = "8799"  # off the default to avoid clashing with a real gateway
URL = f"ws://127.0.0.1:{PORT}"


def main():
    env = dict(os.environ)
    procs = []
    try:
        print("== starting gateway ==")
        procs.append(subprocess.Popen(
            [PY, "gateway.py", "--host", "127.0.0.1", "--port", PORT],
            cwd=HERE, env=env))
        time.sleep(1.5)

        print("== starting node agent (always available) ==")
        procs.append(subprocess.Popen(
            [PY, "agent.py", "--gateway", URL, "--node-id", "demo-node"],
            cwd=HERE, env=env))
        time.sleep(2.0)

        print("== submitting example job ==")
        rc = subprocess.call(
            [PY, "client.py", "--gateway", URL, "--job", "examples/hello_job.json"],
            cwd=HERE, env=env)
        print(f"\n== client exit code: {rc} ==")
        return rc
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
