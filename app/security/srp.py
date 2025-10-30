import os
import srp

N = srp._modp_2048
g = 2


def generate_salt() -> bytes:
    """Function to generate random salt"""
    return os.urandom(16)


def create_verifier(username: str, password: str, salt: bytes) -> bytes:
    """Function to create srp verified"""
    _usr = username.encode("utf-8")
    _pwd = password.encode("utf-8")
    return srp.create_verifier(_usr, _pwd, salt, N, g)[1]
