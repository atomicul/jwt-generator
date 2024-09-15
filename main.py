#!/usr/bin/env python3

from typing import Dict
from copy import copy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime
import os
import sys
import jwt


def main():
    key = get_key()
    save_public_key(key)
    data = get_data()
    tokens = [encode_jwt(row, key) for row in data]
    print(*tokens, sep="\n")


def encode_jwt(data: Dict[str, str], key: rsa.RSAPrivateKey):
    data = copy(data)
    data["iat"] = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    return jwt.encode(data, key, algorithm="RS256")


def get_data():
    lines = sys.stdin.readlines()
    lines = (line.strip() for line in lines)
    lines = (line for line in lines if line != "")
    lines = [line.split(",") for line in lines]

    head = lines[0]
    body = lines[1:]

    return [dict(zip(head, row)) for row in body]


def save_public_key(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> None:
    KEYNAME = "rsa.pub.key"

    if isinstance(key, rsa.RSAPrivateKey):
        save_public_key(key.public_key())

    if isinstance(key, rsa.RSAPublicKey):
        buff = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
        )
        with open(KEYNAME, "wb") as file:
            file.write(buff)


def get_key() -> rsa.RSAPrivateKey:
    KEYNAME = "rsa.key"

    if any(f == KEYNAME for f in os.listdir(".")):
        with open(KEYNAME, "rb") as file:
            key = load_pem_private_key(file.read(), None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError
            return key

    key = rsa.generate_private_key(65537, 2048, default_backend())
    with open(KEYNAME, "wb") as file:
        file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    return key


if __name__ == "__main__":
    main()
