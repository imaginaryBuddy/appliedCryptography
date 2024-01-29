from datetime import datetime
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import serialization

# Helper function for converting strings into byte arrays needed by cryptographic functions
def string_to_bytes(s):
    return s.encode('utf-8')

# This function will ensure that we represent the JSON dictionary as exactly the
# same string every time, otherwise we'd get different hashes while signing
def canonicalize_json(j):
    return json.dumps(j, sort_keys=True)

def verify_identity(issuer_identity, ca_identity):
    if issuer_identity == ca_identity:
        print("VERIFIED: issuer identity and ca identity")
        return True 
    else: 
        print("FAILED: issuer identity not ca identity")
        return False
    
def verify_cert(ca_public_key, message, signature_dict):
    try:
        signature = encode_dss_signature(signature_dict['r'], signature_dict['s'])
        ca_public_key.verify(signature, string_to_bytes(message), ec.ECDSA(hashes.SHA256()))
        print("SUCCESS: certificate verification")
        return True 
    except:
        print("FAILED: certificate verification")
        return False
    
def verify_message(signer_pk, message, signature_dict):
    try:
        signature = encode_dss_signature(signature_dict['r'], signature_dict['s'])
        signer_pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("SUCCESS: message verification")
        return True 
    except: 
        print("FAILED: message verification")
        return False 
    
def verify_validity(cert_body):
    valid_from = datetime.fromisoformat(cert_body['validity start'])
    valid_till = datetime.fromisoformat(cert_body['validity end'])
    current = datetime.now()
    if valid_from <= current and current <= valid_till:
        print("SUCCESS: validity not expired")
        return True 
    else: 
        print("FAILED: validity dates not valid")
        return False


def verify(ca_identity, signed_message_filename): 

    print("Trying to verify " + signed_message_filename)

    # Load the signed message data
    with open(signed_message_filename, 'r') as fh:
        signed_message = json.load(fh)

    # Read out the identity of the signer and load their certificate
    signer_identity = signed_message['signer identity']
    with open(signer_identity + '.cert', 'r') as fh:
        signer_cert = json.load(fh)
    # Format the certificate body for signing as a byte array in a canonical order
    cert_body_to_be_signed = string_to_bytes(canonicalize_json(signer_cert["body"]))

    # Read out the identity of the issuer and load their public key
    issuer_identity = signer_cert['body']['issuer identity']
    signer_pk = serialization.load_pem_public_key(string_to_bytes(signer_cert['body']['public key']))
    with open(ca_identity + '.pk', 'r') as fh:
        ca_public_key = serialization.load_pem_public_key(string_to_bytes(fh.read()))
    # YOUR SOLUTION STARTS HERE

    # Functions that might be of use to you:
    # - datetime.fromisoformat (https://docs.python.org/3/library/datetime.html#datetime.date.fromisoformat)
    # - datetime.now
    # - encode_dss_signature (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature)
    # - ca_public_key.verify and signer_pk.verify (see https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curve-signature-algorithms)

    if not verify_identity(issuer_identity, ca_identity):
        return 
    if not verify_cert(ca_public_key, canonicalize_json(signer_cert['body']), signer_cert['signature']):
        return 
    
    message = string_to_bytes(signed_message['message'])
    message_signature = signed_message['signature']

    if not verify_message(signer_pk, message, message_signature):
        return 
    
    if not verify_validity(signer_cert['body']):
        return 
    

    print("SUCCESS: VERIFIED")

print("Message1")
verify("dstebila", "message1.signed.txt")
print()
print("Message2")
verify("dstebila", "message2.signed.txt")
print()
print("Message3")
verify("dstebila", "message3.signed.txt")
print()
print("Message4")
verify("dstebila", "message4.signed.txt")
print()
print("Message5")
verify("dstebila", "message5.signed.txt")
print()
