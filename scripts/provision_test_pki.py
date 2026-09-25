#!/usr/bin/env python3
"""Provision a TEST public-key infrastructure for a local deployment.

Creates, under --out:
  ca.pem                          deployment CA certificate (trust anchor)
  ca-private/ca.key               CA signing key (test only; keep offline in practice)
  party0.{pem,key}, party1.{pem,key}, coordinator.{pem,key}
  requester-<name>.{pem,key}      CN = requester:<name>
  station-<id>.{pem,key}          CN = station:<id>
  mpspdz/P0.{pem,key}, mpspdz/P1.{pem,key}
                                  self-signed certificates in the layout MP-SPDZ's
                                  CryptoPlayer expects (CN = P0 / P1)

All keys are fresh ECDSA P-256 keys. In a real deployment every principal
generates its own key and only receives a signed certificate; this script
exists so tests and benchmarks can be reproduced on one machine.

Requires the `cryptography` package (pip install cryptography).
"""

import argparse
import datetime
import os
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    os.chmod(path, 0o600)


def write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def validity(builder):
    now = datetime.datetime.now(datetime.timezone.utc)
    return builder.not_valid_before(now - datetime.timedelta(minutes=5)) \
                  .not_valid_after(now + datetime.timedelta(days=30))


def make_ca(out):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = validity(x509.CertificateBuilder()
                       .subject_name(name("pp-search test CA"))
                       .issuer_name(name("pp-search test CA"))
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number()))
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
                     .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                                  False, False), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    (out / "ca-private").mkdir(parents=True, exist_ok=True)
    write_key(out / "ca-private" / "ca.key", key)
    write_cert(out / "ca.pem", cert)
    return key, cert


def issue(out, ca_key, ca_cert, identity):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = validity(x509.CertificateBuilder()
                       .subject_name(name(identity))
                       .issuer_name(ca_cert.subject)
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number()))
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                           ExtendedKeyUsageOID.CLIENT_AUTH]),
                                    critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    stem = identity.replace(":", "-")
    write_key(out / f"{stem}.key", key)
    write_cert(out / f"{stem}.pem", cert)


def self_signed(directory, common_name):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = validity(x509.CertificateBuilder()
                       .subject_name(name(common_name))
                       .issuer_name(name(common_name))
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number()))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    write_key(directory / f"{common_name}.key", key)
    write_cert(directory / f"{common_name}.pem", cert)


def id_list(text):
    return [item for item in text.split(",") if item] if text else []


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--stations", default="", help="comma-separated station IDs")
    parser.add_argument("--stations-file", help="CSV id,x,y,radius; IDs are provisioned")
    parser.add_argument("--requesters", default="", help="comma-separated requester names")
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = make_ca(out)
    identities = ["party0", "party1", "coordinator"]
    identities += [f"requester:{n}" for n in id_list(args.requesters)]
    stations = id_list(args.stations)
    if args.stations_file:
        for line in pathlib.Path(args.stations_file).read_text().splitlines():
            if line and not line.startswith("#"):
                stations.append(line.split(",")[0])
    identities += [f"station:{int(s)}" for s in dict.fromkeys(stations)]
    for identity in identities:
        issue(out, ca_key, ca_cert, identity)

    mpspdz = out / "mpspdz"
    mpspdz.mkdir(exist_ok=True)
    for party in (0, 1):
        self_signed(mpspdz, f"P{party}")
    print(f"provisioned {len(identities)} identities in {out}")


if __name__ == "__main__":
    main()
