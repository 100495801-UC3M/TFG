import tenseal as ts
import socket
import pickle

HOST="127.0.0.1"
PORT=8080

def encrypt_vector(v):

    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60,40,40,60]
    )

    context.generate_galois_keys()
    context.global_scale = 2**40

    enc = ts.ckks_vector(context,v)

    return enc.serialize()

def send_vector(v):

    data = encrypt_vector(v)

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:

        s.connect((HOST,PORT))

        s.send(len(data).to_bytes(8,"little"))
        s.send(data)

        size=int.from_bytes(s.recv(8),"little")
        result=s.recv(size)

        return result