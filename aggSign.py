import argparse, json, time
from typing import Tuple
from schnorr_lib import n, p, G, point_add, int_from_hex, sha256, get_bytes_R_from_sig, lift_x_even_y, get_int_R_from_sig, get_int_s_from_sig, point_mul, xor_bytes, bytes_from_int, tagged_hash, get_aux_rand, int_from_bytes, bytes_from_point

#secp256k1
#T=(p,a,b,G,n,b)

# Generate Aggregate signature
def aggregateSign(inputList: list):
    SigmaAgg=[]
    idx = 1
    S_agg = 0
    allUsersHash = b''
    for user in inputList:
        msg = user[0]
        pubkey = user[1]
        sig = user[2]
        r = get_int_R_from_sig(sig)
        allUsersHash += bytes_from_int(r) + pubkey + msg
    for user in inputList:
        msg = user[0]
        pubkey = user[1]
        sig = user[2]
        if len(msg) != 32:
            raise ValueError('The message must be a 32-byte array.')
        if len(pubkey) != 32:
            raise ValueError('The public key must be a 32-byte array.')
        if len(sig) != 64:
            raise ValueError('The signature must be a 64-byte array.')

        r = get_int_R_from_sig(sig)
        SigmaAgg.append(r)
        s = get_int_s_from_sig(sig)
    
        ei = int_from_bytes(tagged_hash("BIP0340/challenge", allUsersHash + bytes_from_int(idx))) % n
        idx += 1
        S_agg += (ei * s) % n
    SigmaAgg.append(S_agg % n)
    print("Aggregate Signature : ", bytes_from_int(S_agg % p).hex())
    print("Sigma Aggregate : ", SigmaAgg)
    return SigmaAgg


def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    
    f = open('messages.json')
    messages = json.load(f)
    # print("Messages : ", messages)
    f.close()

    f = open('publickeys.json')
    publickeys = json.load(f)
    # print("Public keys : ", publickeys)
    f.close()

    f = open('signatures.json')
    signatures = json.load(f)
    # print("signatures : ", signatures)
    f.close()

    
    inputList = []
    for i in range(len(signatures)):
        inputList.append([sha256(messages[i].encode()), bytes.fromhex(publickeys[i]), bytes.fromhex(signatures[i])])
    
    # print("Input list : ", inputList)

    SigmaAgg = aggregateSign(inputList) 

    json_object = json.dumps(SigmaAgg, indent=4)
    with open("aggregatesign.json", "w") as f:
        f.write(json_object)

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("\n\nAggregate Sign finished in %s seconds\n\n" % (time.time() - start_time))
