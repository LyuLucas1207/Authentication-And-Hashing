from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import base64


class Server():

    def __init__(self, mode_of_operation: str = 'ECB'):
        self.key = get_random_bytes(AES.block_size)
        self.code = base64.b64encode(get_random_bytes(24)).decode('ascii')
        self.mode = mode_of_operation


    def _encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Encrypts the plaintext with AES, returning ciphertext and nonce/iv."""

        match self.mode:
            case 'ECB':
                cipher = AES.new(self.key, AES.MODE_ECB)
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                return ciphertext, bytes(0)
            case 'CBC':
                iv = get_random_bytes(16)
                cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                return ciphertext, iv
            case 'CTR':
                nonce = get_random_bytes(8)
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
                ciphertext = cipher.encrypt(plaintext) # No padding needed in CTR
                return ciphertext, nonce
            case _:
                raise ValueError('Unknown mode of operation')            

    def _decrypt(self, ciphertext: bytes, nonce_or_iv: bytes = bytes(0)) -> bytes:
        """Decrypts the ciphertext with AES, returning plaintext."""

        match self.mode:
            case 'ECB':
                cipher = AES.new(self.key, AES.MODE_ECB)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                return plaintext
            case 'CBC':
                cipher = AES.new(self.key, AES.MODE_CBC, iv=nonce_or_iv)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                return plaintext
            case 'CTR':
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce_or_iv)
                plaintext = cipher.decrypt(ciphertext) # No unpadding needed in CTR
                return plaintext
            case _:
                raise ValueError('Unknown mode of operation')   

    def generate_guest_token(self, name: str, pwd_b64: str) -> tuple[bytes, bytes]:
        """Receives name and password strings, and returns an encrypted user token."""
        # No input sanitization (allows &)
        token_bytes = b'name=' + name.encode('ascii')
        token_bytes += b'&pwd=' + base64.b64decode(pwd_b64.encode('ascii'))
        token_bytes += b'&role=guest'
        token_digest = SHA256.new(data=token_bytes).digest()
        ciphertext, nonce_or_iv = self._encrypt(token_bytes + token_digest)
        return ciphertext, nonce_or_iv

    def read_token(self, enc_token: bytes, nonce_or_iv: bytes = b"", name: str = "", pwd_b64: str = "") -> str:
        """Process an encrypted token and, if correct, returns the role in the token."""
        try:
            pt = self._decrypt(enc_token, nonce_or_iv)

            # Need at least 32 bytes for the SHA-256 digest
            if len(pt) < 32:
                return "other error: token too short"

            token_bytes = pt[:-32]
            recv_digest = pt[-32:]

            # Verify digest (integrity check)
            calc_digest = SHA256.new(data=token_bytes).digest()
            if calc_digest != recv_digest:
                return "wrong digest"

            # Parse k=v pairs from bytes; values may be arbitrary bytes.
            parts = token_bytes.split(b"&")

            data: dict[str, bytes] = {}
            for kv in parts:
                if b"=" not in kv:
                    return "other error malformed field"
                k, v = kv.split(b"=", 1)  # split once only
                try:
                    key = k.decode("ascii")  # keys should be ASCII
                except UnicodeDecodeError:
                    return "other error non-ascii key"
                data[key] = v  # NOTE: later duplicates overwrite earlier ones

            # Required fields
            if "name" not in data or "pwd" not in data or "role" not in data:
                return "other error missing fields"

            # Compare name (must be ASCII)
            try:
                token_name = data["name"].decode("ascii")
            except UnicodeDecodeError:
                return "wrong name"  # or "other error name not ascii"

            if token_name != name:
                return "wrong name"

            # Compare password as raw bytes
            try:
                expected_pwd_bytes = base64.b64decode(pwd_b64, validate=True)
            except Exception:
                return "other error bad pwd_b64"

            if data["pwd"] != expected_pwd_bytes:
                return "wrong pwd"

            # Role should be ASCII text (guest/admin/etc.)
            try:
                role = data["role"].decode("ascii")
            except UnicodeDecodeError:
                return "other error role not ascii"

            return role

        except Exception as e:
            msg = str(e)
            if "Padding is incorrect" in msg:
                return f"incorrect padding {msg}"
            elif "Decrypt error" in msg:
                return f"decrypt error {msg}"
            else:
                return f"other error {msg}"