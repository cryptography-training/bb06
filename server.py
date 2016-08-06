# THIS IS ALL BROKEN< DO NOT USE SERIOUSLY

import hashlib, math, binascii
from flask import Flask, request, abort, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

def egcd(a, b):
    if a == 0: return (0, 1, b)
    y, x, g = egcd(b % a, a)
    return (x - (b // a) * y, y, g)
def invmod(a, m):
    x, y, g = egcd(a, m)
    if g != 1: raise ValueError
    return x % m

def to_bytes(n, byte_len):
    """ Return a bytes representation of a int """
    return n.to_bytes(byte_len, byteorder='big')

def from_bytes(b):
    """ Makes a int from a bytestring """
    return int.from_bytes(b, byteorder='big')

def RSA_generate():
    private_key = rsa.generate_private_key(
        public_exponent=3,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def RSA_encrypt(message, public_key):
    pn = public_key.public_numbers()
    n, e = pn.n, pn.e
    m = from_bytes(message)
    c = pow(m, e, n)
    N = math.ceil(public_key.public_numbers().n.bit_length() / 8.0)
    return to_bytes(c, N)

def RSA_decrypt(ciphertext, private_key):
    pn = private_key.private_numbers()
    d, n = pn.d, pn.public_numbers.n
    c = from_bytes(ciphertext)
    m = pow(c, d, n)
    N = math.ceil(private_key.private_numbers().public_numbers.n.bit_length() / 8.0)
    return to_bytes(m, N)

def PKCS1_v1_5_sign(private_key, message):
    ASN_1_goop = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    hash_data = hashlib.sha1(message.encode('utf8')).digest()
    N = math.ceil(private_key.private_numbers().public_numbers.n.bit_length() / 8.0)
    sig_data = (b'\x01' + b'\xff' * int(N - 3 - len(ASN_1_goop) - len(hash_data))
        + b'\x00' + ASN_1_goop + hash_data)
    return RSA_decrypt(sig_data, private_key).rjust(N, b'\x00')

def RSA_PKCS1_v1_5_verify(public_key, sig, message):
    # "Encrypt" to get the signed message
    sig_data = RSA_encrypt(sig.lstrip(b'\x00'), public_key)

    if sig_data[:2] != b'\x00\x01':
        return False
    sig_data = sig_data[2:]

    while sig_data[0] == 0xff:
        sig_data = sig_data[1:]

    if sig_data[0] != 0x00:
        return False
    sig_data = sig_data[1:]

    # ASN.1 blob for a SHA1 signature
    ASN_1_goop = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    if sig_data[:len(ASN_1_goop)] != ASN_1_goop:
        return False
    sig_data = sig_data[len(ASN_1_goop):]
 
    hash_data = hashlib.sha1(message.encode('utf8')).digest()
    if sig_data[:len(hash_data)] != hash_data:
        return False
    
    return True


private_key = RSA_generate()


@app.route('/')
def show_info():
    return render_template('info.html', n=private_key.private_numbers().public_numbers.n)

@app.route('/api')
def handle_api():
    if not 'name' in request.args: abort(400)
    if not 'sig' in request.args: abort(400)

    sig = binascii.unhexlify(request.args['sig'])
    if not RSA_PKCS1_v1_5_verify(private_key.public_key(), sig, request.args['name']):
        abort(403)

    return 'Welcome user %s!' % request.args['name']


if __name__ == '__main__':
    app.run(port=4242)
