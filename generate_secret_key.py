from ecc_linkable_ring_signatures.linkable_ring_signature import ring_signature, verify_ring_signature, H1
from ecc_linkable_ring_signatures.linkable_ring_signature import export_signature, export_signature_javascript

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.ellipticcurve import Point

import sys
import os

def encrypt(pub_key, message, G=SECP256k1.generator, O=SECP256k1.order):
    k = randrange(O)
    
    P = k * G
    H = k * pub_key

    c = message * H.y() % O

    return (P, c)

def main():
    secret_key = randrange(SECP256k1.order)
    pkey_file = sys.argv[1]

    f = open(pkey_file,'w')
    f.write(str(secret_key) + '\n')
    print("Key is : %s"%(str(secret_key)))

if __name__ == '__main__':
    main()

