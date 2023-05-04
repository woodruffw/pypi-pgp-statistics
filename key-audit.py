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


def _rsa_params(key: dict) -> tuple[int, int]:
    assert key["algorithm"] == "RSA"
    e, n = key["parameters"]["e"], key["parameters"]["n"]

    # For e, we care about the actual value (which is stored as hex).
    # For n, we care about the bitness.
    return (int(e["value"], 16), n["bitness"])


def _dsa_params(key: dict) -> int:
    assert key["algorithm"] == "DSA"

    # We only care about the bitness of p.
    return key["parameters"]["p"]["bitness"]


def _ecdsa_params(key: dict) -> int:
    assert key["algorithm"] == "ECDSA"

    # We only care about the curve, for now.
    return key["parameters"]["curve"]


stats: dict = {
    "total-keys": 0,
    "no-public-key": 0,
    "key-is-subkey": [],
    "unauditable-keys": [],
    "primary-keys-by-algo": defaultdict(int),
    "effective-keys-by-algo": defaultdict(int),
    "rsa-params": {
        "primary": [],
        "effective": [],
    },
    "dsa-params": {
        "primary": [],
        "effective": [],
    },
    "ecdsa-params": {
        "primary": [],
        "effective": [],
    },
}

for line in sys.stdin:
    record = json.loads(line)
    key, keyid = record["key"], record["keyid"]

    stats["total-keys"] += 1

    if key is None:
        stats["no-public-key"] += 1
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

    if primary_key["algorithm"] == "RSA":
        stats["rsa-params"]["primary"].append(_rsa_params(primary_key))
    if key_under_audit["algorithm"] == "RSA":
        stats["rsa-params"]["effective"].append(_rsa_params(key_under_audit))

    if primary_key["algorithm"] == "DSA":
        stats["dsa-params"]["primary"].append(_dsa_params(primary_key))
    if key_under_audit["algorithm"] == "DSA":
        stats["dsa-params"]["effective"].append(_dsa_params(key_under_audit))

    if primary_key["algorithm"] == "ECDSA":
        stats["ecdsa-params"]["primary"].append(_ecdsa_params(primary_key))
    if key_under_audit["algorithm"] == "ECDSA":
        stats["ecdsa-params"]["effective"].append(_ecdsa_params(key_under_audit))

print(json.dumps(stats))
