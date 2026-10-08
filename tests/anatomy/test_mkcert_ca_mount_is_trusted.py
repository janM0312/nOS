"""A mounted mkcert CA is also TRUSTED — mounting it is only half.

Compose fragments bind-mount the estate's mkcert root CA to
``/usr/local/share/ca-certificates/mkcert-ca.crt``. That directory is an INPUT
to ``update-ca-certificates``; a file there is invisible to OpenSSL, PHP, Go
and Node until something builds it into the trust store or points the client
at it. nextcloud:33, linuxserver/bookstack and nfrastack/freescout run no such
step, so their OIDC back-channel to ``auth.<local tld>`` failed with
``certificate verify failed`` and SSO never completed (thisisait/nOS#53) —
verified live: curl/PHP fail before, pass after ``update-ca-certificates``.

Every fragment that mounts the CA there must, in a NON-comment line, also
declare how its client trusts it: an ``update-ca-certificates`` wrapper, or a
client CA variable (SSL_CERT_DIR / SSL_CERT_FILE / NODE_EXTRA_CA_CERTS /
REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE). A comment claiming the image does it is
exactly what nextcloud-base had.
"""

from __future__ import annotations

import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
MOUNT_TARGET = "/usr/local/share/ca-certificates/"
TRUST = (
    "update-ca-certificates",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)


def _code_lines(path: pathlib.Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith("{#"):
            continue
        yield line


def _fragments():
    yield from (REPO / "roles").glob("*/templates/*.j2")
    yield from (REPO / "files/anatomy/plugins").glob("*/templates/*.j2")


def test_fragments_mount_the_ca_somewhere():
    assert any(
        MOUNT_TARGET in line for f in _fragments() for line in _code_lines(f)
    ), "gate went blind: no fragment mounts the mkcert CA"


def test_every_ca_mount_declares_its_trust():
    untrusted = []
    for frag in _fragments():
        code = list(_code_lines(frag))
        if not any(MOUNT_TARGET in line for line in code):
            continue
        if not any(t in line for line in code for t in TRUST):
            untrusted.append(str(frag.relative_to(REPO)))
    assert not untrusted, (
        "mounts the mkcert CA into /usr/local/share/ca-certificates/ but never "
        "trusts it (no update-ca-certificates wrapper / client CA env in code):\n  "
        + "\n  ".join(sorted(untrusted))
    )
