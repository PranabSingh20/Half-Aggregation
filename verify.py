import argparse, sys, time
from utils import print_fails, print_success
from schnorr_lib import n, G, p, sha256, lift_x_even_y, get_int_R_from_sig, get_int_s_from_sig, int_from_bytes, tagged_hash, get_bytes_R_from_sig, point_add, point_mul

# Verify Schnorr signature
def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x_even_y(pubkey)
    r = get_int_R_from_sig(sig)
    s = get_int_s_from_sig(sig)
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", get_bytes_R_from_sig(sig) + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    print(R)
    if (R is None) or (not (R[1] % 2 == 0)):
        return False
    if R[0] != r:
        return False
    return True

def main():
    parser = argparse.ArgumentParser(
        description='It checks the validity of the sign and returns True or False from a public key, a message and a signature')
    parser.add_argument('-s', '--signature', type=str, required=True, help='signature')
    parser.add_argument("-p", "--public_key", type=str, required=True, help='Public key or public aggregate X~')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message')
    
    args = parser.parse_args()
    pubkey = args.public_key
    msg = args.message
    sig = args.signature
    
    try: 
        msg_bytes = sha256(msg.encode())
        sig_bytes = bytes.fromhex(sig)
        pubkey_bytes = bytes.fromhex(pubkey)

        result = schnorr_verify(msg_bytes, pubkey_bytes, sig_bytes)
        print("\nThe signature is: ", sig)
        print("The public key is: ", pubkey)
        print('The message digest is:', msg_bytes.hex())
        print("\nIs the signature valid for this message and this public key? ")
        if result:
            print_success("Yes")
        else:
            print_fails("No")
    except Exception as e:
        print_fails("Exception:", e)
        sys.exit(2)

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("\n\nExecution finished in %s seconds " % (time.time() - start_time))
 

