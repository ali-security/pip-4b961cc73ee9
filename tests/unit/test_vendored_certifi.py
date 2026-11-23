"""Tests for the CA bundle pip ships in its vendored copy of certifi."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from pip._vendor import certifi

# Root certificates that were removed from the Mozilla trust store and must
# not be trusted by pip (CVE-2026-133949), keyed by their SHA-256 fingerprint.
DISTRUSTED_ROOTS = {
    "Atos TrustedRoot 2011": (
        "f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474"
    ),
    "emSign ECC Root CA - G3": (
        "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
    ),
}


@pytest.fixture(scope="module")
def trusted_fingerprints() -> set[str]:
    # Load the bundle the same way pip and requests do by default, so the
    # check covers the certificates that actually end up being trusted.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=certifi.where())
    ca_certs = ctx.get_ca_certs(binary_form=True)
    # Guard against a vacuous pass if the bundle failed to load.
    assert len(ca_certs) > 100
    return {hashlib.sha256(der).hexdigest() for der in ca_certs}


@pytest.mark.parametrize(
    "fingerprint",
    list(DISTRUSTED_ROOTS.values()),
    ids=list(DISTRUSTED_ROOTS),
)
def test_distrusted_root_not_trusted(
    trusted_fingerprints: set[str], fingerprint: str
) -> None:
    assert fingerprint not in trusted_fingerprints


@pytest.mark.parametrize(
    "fingerprint",
    list(DISTRUSTED_ROOTS.values()),
    ids=list(DISTRUSTED_ROOTS),
)
def test_distrusted_root_not_in_bundle_contents(fingerprint: str) -> None:
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    fingerprints = set()
    for block in certifi.contents().split(end):
        if begin not in block:
            continue
        pem_cert = block[block.index(begin) :] + end + "\n"
        der = ssl.PEM_cert_to_DER_cert(pem_cert)
        fingerprints.add(hashlib.sha256(der).hexdigest())
    assert len(fingerprints) > 100
    assert fingerprint not in fingerprints
