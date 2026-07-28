"""authctl — manage the gateway's approved-keys store (Phase 3 secure mode).

Participants (nodes, requesters) authenticate with an Ed25519 keypair. This tool
lets the gateway admin see who has requested access and approve or revoke them.

    python authctl.py --keys authorized_keys.json list
    python authctl.py --keys authorized_keys.json pending
    python authctl.py --keys authorized_keys.json approve <fingerprint|pubkey> [--label name]
    python authctl.py --keys authorized_keys.json revoke  <fingerprint|pubkey>
    python authctl.py --keys authorized_keys.json add <pubkey> --role node --label gpu139 --approve

A key first appears (as `pending`) automatically the moment its owner tries to
connect; `approve` it and they're in on their next reconnect (no gateway restart).
"""

import argparse
import sys
from datetime import datetime, timezone

import identity as ID

DEFAULT_KEYS = "authorized_keys.json"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _resolve(keys: dict, needle: str):
    """Find a pubkey by exact match or by fingerprint (prefix)."""
    if needle in keys:
        return needle
    matches = [pk for pk in keys
               if ID.fingerprint_of(pk) == needle
               or ID.fingerprint_of(pk).startswith(needle)
               or pk.startswith(needle)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"ambiguous '{needle}' matches {len(matches)} keys; use the full fingerprint", file=sys.stderr)
        sys.exit(2)
    return None


def _fmt_row(pubkey, entry):
    fp = entry.get("fingerprint") or ID.fingerprint_of(pubkey)
    status = entry.get("status", "?")
    mark = {"approved": "[+]", "pending": "[.]", "revoked": "[-]"}.get(status, "[?]")
    label = entry.get("label") or ""
    role = entry.get("role") or ""
    return f"  {mark} {fp}  {status:<8} {role:<10} {label}"


def cmd_list(keys, args, only=None):
    rows = [(pk, e) for pk, e in keys.items() if only is None or e.get("status") == only]
    if not rows:
        print("(no keys)" if only is None else f"(no {only} keys)")
        return
    for pk, e in sorted(rows, key=lambda x: (x[1].get("status", ""), x[1].get("label", ""))):
        print(_fmt_row(pk, e))


def cmd_approve(keys, args):
    pk = _resolve(keys, args.key)
    if pk is None:
        print(f"no key matches '{args.key}'", file=sys.stderr)
        sys.exit(1)
    keys[pk]["status"] = "approved"
    keys[pk]["approved_at"] = _now()
    if args.label:
        keys[pk]["label"] = args.label
    ID.save_keystore(args.keys, keys)
    print(f"approved {ID.fingerprint_of(pk)}  ({keys[pk].get('label') or 'no label'})")


def cmd_revoke(keys, args):
    pk = _resolve(keys, args.key)
    if pk is None:
        print(f"no key matches '{args.key}'", file=sys.stderr)
        sys.exit(1)
    keys[pk]["status"] = "revoked"
    keys[pk]["revoked_at"] = _now()
    ID.save_keystore(args.keys, keys)
    print(f"revoked {ID.fingerprint_of(pk)}")


def cmd_add(keys, args):
    pk = args.key
    try:
        ID.unb64(pk)
    except Exception:
        print("that doesn't look like a base64 public key", file=sys.stderr)
        sys.exit(2)
    keys[pk] = {
        "role": args.role, "label": args.label or "",
        "status": "approved" if args.approve else "pending",
        "fingerprint": ID.fingerprint_of(pk), "first_seen": _now(),
    }
    if args.approve:
        keys[pk]["approved_at"] = _now()
    ID.save_keystore(args.keys, keys)
    print(f"added {ID.fingerprint_of(pk)} as {keys[pk]['status']}")


def main():
    ap = argparse.ArgumentParser(description="Manage the gateway approved-keys store")
    ap.add_argument("--keys", default=DEFAULT_KEYS, help=f"keys JSON file (default {DEFAULT_KEYS})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="show all keys")
    sub.add_parser("pending", help="show keys awaiting approval")

    p = sub.add_parser("approve", help="approve a key")
    p.add_argument("key"); p.add_argument("--label")
    p = sub.add_parser("revoke", help="revoke a key")
    p.add_argument("key")
    p = sub.add_parser("add", help="add a key directly")
    p.add_argument("key"); p.add_argument("--role", default="node")
    p.add_argument("--label"); p.add_argument("--approve", action="store_true")

    args = ap.parse_args()
    keys = ID.load_keystore(args.keys)

    if args.cmd == "list":
        cmd_list(keys, args)
    elif args.cmd == "pending":
        cmd_list(keys, args, only="pending")
    elif args.cmd == "approve":
        cmd_approve(keys, args)
    elif args.cmd == "revoke":
        cmd_revoke(keys, args)
    elif args.cmd == "add":
        cmd_add(keys, args)


if __name__ == "__main__":
    main()
