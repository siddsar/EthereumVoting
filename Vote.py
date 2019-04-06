from ecc_linkable_ring_signatures.linkable_ring_signature import ring_signature, verify_ring_signature, H1
from ecc_linkable_ring_signatures.linkable_ring_signature import export_signature, export_signature_javascript

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.ellipticcurve import Point

import sys
import os


def pointify(pk):
    return Point(curve_secp256k1, int(pk[0]), int(pk[1]))


def encrypt(pub_key, message, G=SECP256k1.generator, O=SECP256k1.order):
    k = randrange(O)
    
    P = k * G
    H = k * pub_key

    c = message * H.y() % O

    return (P, c)

ring_path = sys.argv[1]
secret_key_path = sys.srgv[2]
threshold_key_path = sys.argv[3]
vote_option = int(sys.argv[4])
saved_vote_path = sys.argv[5]
ring = []

for pubkey in open(ring_path,'r').readlines():
    ring.append(pointify(pubkey[:,-1].split(',')))

f = open(threshold_key_path,'r')
threshold_key = pointify(f.readlines()[0][:,-1])

f = open(secret_key_path,'r')
secret_key = pointify(f.readlines()[0][:,-1])

v = encrypt( threshold_key, vote_option)

vote = [v[0].x() , v[0].y() , v[1]]

user_idx = 0

for i in range(len(ring)):
    if SECP256k1.generator * secret_key == ring[i]:
        user_idx = i

signature = ring_signature(secret_key, j, H1(vote), ring)
assert(verify_ring_signature(H1(vote), ring, *sig))

export_signature( ring, vote, '.', saved_vote_path)





