"""Question 1: identify each SHA digest, then recover the password.

Two different steps:

1. The hexadecimal length fixes the output size (one hex character is 4 bits).
   Several SHA functions can share that size, so length only gives candidates.
2. The assignment says every password is in the dictionary. A hash has no
   inverse, so each dictionary word is hashed with every candidate and compared
   with the digest. The match names both the algorithm and the password.
"""

import hashlib
from pathlib import Path

# Digests from the assignment, in the order given.
DIGESTS = [
    "8a81e9a2dbdc9ccf4ac5091a8a3458b529de766c3320138cf1f9708e537afb01",
    "da938a3a3165693b72dddaa29453919ec9e82803c2510af6dc54efa5",
    "a5b23f338648cb6f21e2cc1284e4d1b7b930ac97",
]

# Output length in hex characters -> SHA functions hashlib can compute.
# 40 chars = 160 bits, 56 = 224 bits, 64 = 256 bits.
CANDIDATES_BY_HEX_LENGTH = {
    40: ["sha1"],
    56: ["sha224", "sha3_224", "sha512_224"],
    64: ["sha256", "sha3_256", "sha512_256"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512"],
}

DISPLAY_NAME = {
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "sha512_224": "SHA-512/224",
    "sha512_256": "SHA-512/256",
}

DICTIONARY = Path(__file__).resolve().parent.parent / "hashing" / "password.lst"


def candidates_for(digest: str) -> list[str]:
    """SHA functions whose digest has the same hexadecimal length."""
    algorithms = CANDIDATES_BY_HEX_LENGTH.get(len(digest))
    if algorithms is None:
        raise ValueError(f"unrecognized digest length {len(digest)}")
    return algorithms


def load_dictionary(path: Path) -> list[str]:
    """Read candidate passwords, skipping the wordlist's #! comment lines."""
    passwords = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#!"):
                continue
            password = line.rstrip("\r\n")
            if password:
                passwords.append(password)
    return passwords


def recover(dictionary: list[str], digests: list[str]) -> dict[str, tuple[str, str]]:
    """Hash every dictionary word with each length-matched SHA function.

    Returns a map from digest to (algorithm, password). Each digest must
    match exactly once.
    """
    pending = {digest: candidates_for(digest) for digest in digests}
    found: dict[str, tuple[str, str]] = {}
    for password in dictionary:
        password_bytes = password.encode("utf-8")
        for digest, algorithms in list(pending.items()):
            for algorithm in algorithms:
                candidate = hashlib.new(algorithm, password_bytes).hexdigest()
                if candidate == digest:
                    if digest in found:
                        previous = found[digest]
                        raise RuntimeError(
                            f"{digest} matches both {previous} and {(algorithm, password)}"
                        )
                    found[digest] = (algorithm, password)
                    del pending[digest]
                    break
        if not pending:
            break
    if pending:
        missing = ", ".join(pending)
        raise RuntimeError(f"passwords not found for: {missing}")
    return found


def main() -> None:
    print("Step 1: digest length gives the candidate algorithms")
    for index, digest in enumerate(DIGESTS, start=1):
        names = ", ".join(DISPLAY_NAME[name] for name in candidates_for(digest))
        print(f"  digest {index}: {len(digest)} hex chars -> {names}")

    dictionary = load_dictionary(DICTIONARY)
    print(f"\nStep 2: hash each of {len(dictionary)} dictionary passwords")
    found = recover(dictionary, DIGESTS)
    print("\nMatch (algorithm and password):")
    for index, digest in enumerate(DIGESTS, start=1):
        algorithm, password = found[digest]
        print(f"  digest {index}: {DISPLAY_NAME[algorithm]}, password {password}")


if __name__ == "__main__":
    main()
