from srptools import SRPContext
from srptools.constants import PRIME_2048, PRIME_2048_GEN

PRIME = PRIME_2048
GENERATOR = PRIME_2048_GEN


def create_verifier(username: str, password: str, salt_hex: str) -> str:
    """Function to create srp verified"""
    salt_int = int(salt_hex, 16)
    ctx = SRPContext(username, password, prime=PRIME, generator=GENERATOR)
    password_hash = ctx.get_common_password_hash(salt_int)
    verifier_int = ctx.get_common_password_verifier(password_hash)
    return format(verifier_int, "x")


def get_constants() -> dict:
    return {"N": PRIME, "g": GENERATOR}
