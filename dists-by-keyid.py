#!/usr/bin/env python

# dists-by-keyid:
#   take a list of PyPI hosted distributions by filename
#   on stdin, retrieve the corresponding PGP signature
#   for each, and group the distributions by key ID.

from collections import defaultdict
import csv
import json
import sys

import pgpy
import requests

_SIGNATURE_URL_FORMAT = (
    "https://files.pythonhosted.org/packages/{chunked_digest}/{dist}.asc"
)

# map of key ID -> distributions signed by that key
_KEY_ID_MAP: dict[str, list[dict[str, str]]] = defaultdict(list)


def keyid_for_sig(sig: pgpy.PGPSignature) -> str:
    return sig.signer


io = csv.DictReader(sys.stdin)
for rec in io:
    digest = rec["blake2_256_digest"]
    chunked_digest = f"{digest[0:2]}/{digest[2:4]}/{digest[4:]}"
    sig_url = _SIGNATURE_URL_FORMAT.format(
        chunked_digest=chunked_digest,
        dist=rec["filename"],
    )
    print(f"retrieving: {sig_url}", file=sys.stderr)
    sig_resp = requests.get(sig_url)

    try:
        sig_resp.raise_for_status()
    except:
        print(f"barf: {sig_resp.status_code}, probably my fault", file=sys.stderr)
        _KEY_ID_MAP[f"<HTTP {sig_resp.status_code}>"].append(rec)
        continue

    sig = pgpy.PGPSignature.from_blob(sig_resp.content)
    try:
        # https://github.com/SecurityInnovation/PGPy/issues/433
        sig
        sig.signer
    except AttributeError:
        print("barf: couldn't get signer, probably ancient", file=sys.stderr)
        _KEY_ID_MAP["<invalid signer>"].append(rec)
        continue

    _KEY_ID_MAP[sig.signer].append(rec)

print(json.dumps(_KEY_ID_MAP))
