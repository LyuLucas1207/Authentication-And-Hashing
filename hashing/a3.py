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


def online_attack(check_password: Callable[[str], tuple[bool, int]]) -> str:
    """This attack receives a check_password function which
    takes as input a candidate password and returns whether
    the password was correct/incorrect and the (virtual) time
    it took to check the password correctness.
    The attack should output the correct password."""

    pwd = ''
    return pwd


def forge_admin_token_cbc_hash(
        generate_guest_token: Callable[[str, str], tuple[bytes, bytes]],
        ) -> tuple[bytes, bytes, str, str]:
    """Implements attacker for Q9"""
    ciphertext_token = bytes(0)
    iv = bytes(0)
    name = 'test_name'
    pwd_b64 = base64.b64encode(b'test_pwd').decode('ascii')
    return ciphertext_token, iv, name, pwd_b64