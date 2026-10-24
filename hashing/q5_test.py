import timeit
import string
import random
import hashlib
import bcrypt

VALID_CHARS = string.digits + string.ascii_letters + string.punctuation
ROUNDS = 4
PWD_LENGTH = 12

def bcrypt_hash_test():
    pwd = ''.join(random.choices(VALID_CHARS, k=PWD_LENGTH)).encode('ascii')
    salt = bcrypt.gensalt(ROUNDS)
    fingerprint = bcrypt.hashpw(pwd, salt)
    return fingerprint

def sha_hash_test():
    pwd = ''.join(random.choices(VALID_CHARS, k=PWD_LENGTH))
    fingerprint = hashlib.sha256(pwd.encode('ascii')).hexdigest()
    return fingerprint

if __name__=="__main__":
    hash_number = 10000
    runtime = timeit.timeit(bcrypt_hash_test, number=hash_number)
    print(f"Using bcrypt with {ROUNDS} rounds, my computer can compute {hash_number/runtime:.1f} hashes per second")
    runtime = timeit.timeit(sha_hash_test, number=hash_number)
    print(f"Using SHA-256, my computer can compute {hash_number/runtime:.1f} hashes per second")