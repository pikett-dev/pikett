"""Key helpers: `python -m runner.keys public` derives the public key from the seed in RUNNER_SIGNING_KEY."""

import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def private_key_from_b64(seed: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed.strip(), validate=True))
    except ValueError as error:
        raise ValueError("the signing key must be a 32 byte seed in base64") from error


def public_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")


if __name__ == "__main__":
    if sys.argv[1:] != ["public"]:
        sys.exit("usage: RUNNER_SIGNING_KEY=<seed> python -m runner.keys public")
    print(public_b64(private_key_from_b64(os.environ["RUNNER_SIGNING_KEY"])))
