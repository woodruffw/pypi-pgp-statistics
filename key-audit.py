#!/usr/bin/env python

# key-audit:
#   take a JSONL stream in the same produced by `all-dist-keys.py`
#   and run some basic "audits" on the keys for algorithm, key size, etc.

from collections import defaultdict
import json
import os
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile

_PGPKEYDUMP_BINARY = os.getenv("PGPKEYDUMP", shutil.which("pgpkeydump"))
if not _PGPKEYDUMP_BINARY:
    raise ValueError("missing pgpkeydump binary to dump with")

stats: dict = {
    "total-keys": 0,
    "key-is-subkey": [],
    "no-public-key": [],
    "unauditable-keys": [],
    "primary-keys-by-algo": defaultdict(int),
    "effective-keys-by-algo": defaultdict(int),
}

for line in sys.stdin:
    record = json.loads(line)
    key, keyid = record["key"], record["keyid"]

    stats["total-keys"] += 1

    if key is None:
        stats["no-public-key"].append(keyid)
        continue

    with NamedTemporaryFile(mode="w") as f:
        f.write(key)
        f.flush()
        try:
            result = subprocess.run(
                [_PGPKEYDUMP_BINARY, f.name], check=True, capture_output=True
            )
        except subprocess.CalledProcessError as exc:
            print(f"{keyid}: {exc.stderr.decode()}", file=sys.stderr)
            print(key, file=sys.stderr)
            stats["unauditable-keys"].append(keyid)
            continue

    audit = json.loads(result.stdout)
    primary_key, subkeys = audit["primary_key"], audit["subkeys"]

    if keyid != primary_key["keyid"]:
        stats["key-is-subkey"].append((primary_key["keyid"], keyid))
        key_under_audit = next(k for k in subkeys if k["keyid"] == keyid)
    else:
        key_under_audit = primary_key

    stats["primary-keys-by-algo"][primary_key["algorithm"]] += 1
    stats["effective-keys-by-algo"][key_under_audit["algorithm"]] += 1

# print(
#     f"number of key IDs without a publicly discoverable key: {len(stats['no-public-key'])}",
#     file=sys.stderr,
# )

print(json.dumps(stats))
