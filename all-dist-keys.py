#!/usr/bin/env python

# all-dist-keys:
#   take a JSON stream in the shape emitted by
#   `dists-by-keyid.py` and emit a JSONL stream
#   of PGP keys (one armored key per record)

import json
import sys
from time import sleep
from typing import Any

import requests


_DISTS_BY_KEYID: dict[str, Any] = json.load(sys.stdin)


def _get_key_by_keyid(keyid: str):
    url = f"https://keys.openpgp.org/vks/v1/by-keyid/{keyid}"
    print(url, file=sys.stderr)
    resp = requests.get(url)

    key = None
    if not resp.ok:
        if resp.status_code == 404:
            print(f"keys.openpgp.org: no key found for ID: {keyid}", file=sys.stderr)
        else:
            resp.raise_for_status()
    else:
        print(f"got key for {keyid}!", file=sys.stderr)
        key = resp.content.decode()
        print(json.dumps({"keyid": keyid, "key": key}))
        return

    print(f"{keyid}: trying harder...", file=sys.stderr)
    prefixed = f"0x{keyid}"
    resp = requests.get(f"https://keyserver.ubuntu.com/pks/lookup?search={prefixed}&op=get")
    if not resp.ok:
        if resp.status_code == 404:
            print(f"keyserver.ubuntu.com: no key found for ID: {keyid}", file=sys.stderr)
        else:
            resp.raise_for_status()
    else:
        print(f"paid off: got key for {keyid}!", file=sys.stderr)
        key = resp.content.decode()
        # There's no telling what people are capable of these days.
        assert key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")

    print(json.dumps({"keyid": keyid, "key": key}))



for keyid in _DISTS_BY_KEYID.keys():
    if keyid in ["<HTTP 404>", "<invalid signer>"]:
        continue
    _get_key_by_keyid(keyid)
    # Too lazy to do ratelimiting backoff correctly.
    sleep(0.2)
