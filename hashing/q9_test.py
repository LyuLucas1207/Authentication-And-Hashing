import importlib
from q9_server import Server
from time import time

attacker = importlib.import_module("a3")

def test_forge_token_cbc_hash():

    server = Server('CBC')
    enc_token, nonce_or_iv, name, pwd = attacker.forge_admin_token_cbc_hash(server.generate_guest_token)

    # Grade the result of your attack
    result = server.read_token(enc_token, nonce_or_iv, name, pwd)
    print(f'  Server output from forged token: {result}')
    match result:
        case 'user':
            return 0
        case 'admin':
            return 30
        case 'super_admin':
            return 45
        case _:
            return 0


if __name__=="__main__":

    t0 = time()
    print(f'CBC hash forge: {test_forge_token_cbc_hash()}pt, elapsed time {time()-t0:.1}s')
