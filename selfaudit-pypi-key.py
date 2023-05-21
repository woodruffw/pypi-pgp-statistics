#!/usr/bin/env python3
"""
Self-audit the GPG signing key of a PyPI project.

Synapsis: selfaudit-pypi-key.py projectname

Copyright (c) 2023 Johannes Buchner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import sys
import requests
import subprocess

session = requests.Session()

def download_file(url, filename):
    r = requests.get(url)
    with open(filename, 'wb') as fd:
        fd.write(r.content)


projectname = sys.argv[1]

r = session.get('https://pypi.org/pypi/{}/json'.format(projectname))
assert r.status_code == 200, ('pypi returned status %d for %s' % (r.status_code, projectname))
projectinfo = r.json()

for ver, releases in projectinfo['releases'].items():
    print(ver, 'signed' if any([release['has_sig'] for release in releases]) else 'unsigned')

assert any([release['has_sig'] for release in releases]), ('latest release "{}" not signed!'.format(ver))

any_failures = False
tmpkeyring = './{}-keyring.gpg'.format(projectname)

for release in releases:
    assert release['has_sig'], ('in latest version "{}", file {} is not signed!'.format(ver, release['filename']))

    keyfile = release['url'] + '.asc'
    print("fetching signature file", release['filename'] + '.asc', "...")
    download_file(keyfile, release['filename'] + '.asc')
    print("fetching release file", release['filename'], "...")
    download_file(release['url'], release['filename'])
    ok_here = False
    for keyserver in 'keys.openpgp.org', 'keyserver.ubuntu.com', 'certserver.pgp.com':
        args = ['gpg', '--verify', '--keyserver', keyserver, '--no-default-keyring', '--keyring', tmpkeyring,  '--auto-key-import', '--auto-key-retrieve', release['filename'] + '.asc']
        print('running:', ' '.join(args))
        try:
            result = subprocess.check_output(args, text=True)
            print(result)
            for line in result.split('\n'):
                if 'Good signature from' in line and '[expired]' not in line and '[revoke' not in line:
                    ok_here = True
                    print("ok")
            break
        except subprocess.CalledProcessError:
            print("not successful!")
    if not ok_here:
        any_failures = True
        break

# import os
# if os.path.exists(tmpkeyring):
#     os.unlink(tmpkeyring)

sys.exit(-1 if any_failures else 0)
