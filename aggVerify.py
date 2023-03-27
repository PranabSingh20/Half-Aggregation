import argparse, json, time
from utils import print_fails, print_success
from typing import Tuple
from schnorr_lib import n, p, G, point_add, int_from_hex, sha256, get_bytes_R_from_sig, lift_x_even_y, get_int_R_from_sig, get_int_s_from_sig, point_mul, xor_bytes, bytes_from_int, tagged_hash, get_aux_rand, int_from_bytes, bytes_from_point


# Aggregate Verify
def aggregateVerify(inputList: list, SigmaAgg: list):
    idx = 1
    S_agg = SigmaAgg[len(SigmaAgg)-1]
    allUsersHash = b''
    lhs = None
    for i in range(0, len(SigmaAgg)-1):
        msg = inputList[i][0]
        pubkey = inputList[i][1]
        r = SigmaAgg[i]
        allUsersHash += bytes_from_int(r) + pubkey + msg
    for user in inputList:
        msg = user[0]
        pubkey = user[1]
        r = SigmaAgg[idx-1]
        if len(msg) != 32:
            raise ValueError('The message must be a 32-byte array.')
        if len(pubkey) != 32:
            raise ValueError('The public key must be a 32-byte array.')

        P = lift_x_even_y(pubkey)
        R = lift_x_even_y(bytes_from_int(r))
        ei = int_from_bytes(tagged_hash("BIP0340/challenge", allUsersHash + bytes_from_int(idx))) % n
        idx += 1
        li = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_int(r) + pubkey + msg)) % n
        si = point_add(R, point_mul(P, li))
        if(lhs == None):
            lhs = point_mul(si, ei)
        else:
            lhs = point_add(lhs, point_mul(si, ei))
    rhs = point_mul(G, S_agg)
    print("lhs : ", lhs)
    print("rhs : ", rhs)
    return lhs == rhs

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

    f = open('aggregatesign.json')
    SigmaAgg = json.load(f)
    # print("Aggregate signature : ", SigmaAgg)
    f.close()

    inputList = []

    for i in range(len(messages)):
        inputList.append([sha256(messages[i].encode()), bytes.fromhex(publickeys[i])])

    verify = aggregateVerify(inputList, SigmaAgg)
    if(verify):
        print_success("Yes")
    else:
        print_fails("No")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("\n\nAggregate Verify finished in %s seconds\n\n" % (time.time() - start_time))
