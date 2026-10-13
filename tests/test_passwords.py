import time

import pytest

from iotsec.passwords import hash_password, is_valid_hash, verify_password


def test_roundtrip():
    encoded = hash_password("correct horse battery")
    assert is_valid_hash(encoded) and encoded.startswith("scrypt$32768$8$1$")
    assert verify_password("correct horse battery", encoded)
    assert not verify_password("correct horse batterY", encoded)
    assert hash_password("correct horse battery") != encoded  # salted


def test_short_passwords_are_refused():
    with pytest.raises(ValueError):
        hash_password("short")


@pytest.mark.parametrize("encoded", [
    "", "plain", "scrypt$1$8$1$AAAA$AAAA", "md5$1$1$1$a$b",
    "scrypt$1048577$8$1$AAAA$AAAA", "scrypt$32768$99$1$AAAA$AAAA", "scrypt$32768$8$1$!!$AAAA",
])
def test_malformed_hashes_never_verify(encoded):
    assert not verify_password("anything-long-enough", encoded)


def test_cost_parameters_are_bounded():
    # a hash demanding absurd memory must be rejected without being computed
    started = time.monotonic()
    assert not verify_password("x" * 20, "scrypt$1073741824$8$1$AAAAAAAA$AAAAAAAA")
    assert time.monotonic() - started < 0.5
