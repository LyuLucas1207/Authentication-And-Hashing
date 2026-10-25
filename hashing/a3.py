import hashlib
import bcrypt
import random
import os
import base64
import string
from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


def offline_dictionary_attack(dictionary: list[str], digests: list[str]) -> list[str]:
    """This attack receives a list of strings as dictionary of possible passwords, and another list of strings as bcrypt digests in modular crypt format.
    It returns the list of passwords that generated those digests, in the same order as the digests."""

    pwd_list = [''] * len(digests)
    # "$2b$" + cost + "$" + 22-character salt. Digests with the same
    # prefix share one bcrypt computation per candidate password.
    groups: dict[str, dict[str, list[int]]] = {}
    for index, digest in enumerate(digests):
        setting = digest[:29]
        groups.setdefault(setting, {}).setdefault(digest, []).append(index)

    for setting, targets in groups.items():
        bcrypt_setting = setting.encode("ascii") # include prefix, cost, and salt
        for password in dictionary:
            computed = bcrypt.hashpw(password.encode("utf-8"), salt=bcrypt_setting).decode("ascii")
            indices = targets.pop(computed, None)
            if indices is None: 
                continue
            for index in indices:
                pwd_list[index] = password
            if not targets:
                break
    return pwd_list


# Same alphabet the server samples from. Each check adds at least 1 virtual time.
_ALPHABET = string.digits + string.ascii_letters + string.punctuation


def _password_length(check_password: Callable[[str], tuple[bool, int]]) -> tuple[int, str | None]:
    """A wrong length returns virtual time 0. The password length is 5 to 10."""
    for size in range(5, 11):
        probe = _ALPHABET[0] * size
        ok, elapsed = check_password(probe)
        if ok:
            return size, probe
        if elapsed:
            return size, None
    raise RuntimeError("password length was not between 5 and 10")


def _extend_prefix(
        check_password: Callable[[str], tuple[bool, int]],
        prefix: str,
        length: int,
        ) -> str:
    """Recover one more character, or the whole password if a guess is accepted.

    A wrong guess at this position is checked exactly n = len(prefix)+1 times.
    Every check adds at least 1, so virtual time n means every delay was 1 and
    the guess is certainly wrong. Time above 4n means more than n checks ran,
    so the guess is certainly right.
    """
    checks_if_wrong = len(prefix) + 1
    wrong_max = 4 * checks_if_wrong
    filler = "0" * (length - len(prefix) - 1)
    pending = list(_ALPHABET)
    while len(pending) > 1:
        still_possible = []
        for char in pending:
            candidate = prefix + char + filler
            ok, elapsed = check_password(candidate)
            if ok:
                return candidate
            if elapsed > wrong_max:
                return prefix + char
            if elapsed > checks_if_wrong:
                still_possible.append(char)
        if not still_possible:
            raise RuntimeError("every candidate was rejected")
        pending = still_possible
    return prefix + pending[0]


def online_attack(check_password: Callable[[str], tuple[bool, int]]) -> str:
    """This attack receives a check_password function which
    takes as input a candidate password and returns whether
    the password was correct/incorrect and the (virtual) time
    it took to check the password correctness.
    The attack should output the correct password."""

    length, found = _password_length(check_password)
    if found is not None:
        return found
    prefix = ""
    while len(prefix) < length - 1:
        prefix = _extend_prefix(check_password, prefix, length)
        if len(prefix) == length:
            return prefix
    for char in _ALPHABET:
        candidate = prefix + char
        ok, _elapsed = check_password(candidate)
        if ok:
            return candidate
    raise RuntimeError("last character was not found")


def forge_admin_token_cbc_hash(
        generate_guest_token: Callable[[str, str], tuple[bytes, bytes]],
        ) -> tuple[bytes, bytes, str, str]:
    """Implements attacker for Q9.

    Build the super_admin message and its SHA-256 first, hide that suffix
    inside the password, and let the server CBC-encrypt it. Then keep only
    the ciphertext blocks that cover the message, digest, and padding.
    """
    name = "lucas"
    password = b"127"
    message = b"name=" + name.encode("ascii") + b"&pwd=" + password + b"&role=super_admin"
    digest = SHA256.new(data=message).digest()
    # PKCS#7 so the forged plaintext ends on an AES block boundary.
    padded = pad(message + digest, AES.block_size)
    suffix = padded[len(message):]

    # Server writes name=...&pwd=<this>&role=guest, then encrypts.
    injected = password + b"&role=super_admin" + suffix
    ciphertext, iv = generate_guest_token(name, base64.b64encode(injected).decode("ascii"))
    # Drop the blocks that encrypt &role=guest and the server's own digest.
    ciphertext = ciphertext[:len(padded)]
    # read_token compares the parsed pwd field, which is only the real password.
    return ciphertext, iv, name, base64.b64encode(password).decode("ascii")