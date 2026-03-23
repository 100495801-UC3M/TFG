"""
app/test.py  —  Cliente de prueba (Windows)
=============================================
Envía dos listas cifradas con SEAL (CKKS) al servidor WSL.
El servidor realiza la operación indicada de forma COMPLETAMENTE cifrada
y devuelve el resultado cifrado; este script lo descifra aquí.

Requiere: tenseal  (pip install tenseal)
          El servidor test_server debe estar corriendo en WSL.
"""

import socket
import struct
import tempfile
import os
import tenseal.sealapi as seal   # bindings nativos de SEAL, mismo formato que C++

# ──────────────────────────────────────────────
#  Configuración de red
#  WSL2: 127.0.0.1 suele funcionar con port-forwarding.
#  Si no, obtén la IP con:  wsl hostname -I
# ──────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8080


# ══════════════════════════════════════════════
#  SEAL helpers
# ══════════════════════════════════════════════

def crear_contexto():
    """Mismos parámetros que test_servidor.cpp."""
    parms = seal.EncryptionParameters(seal.SCHEME_TYPE.CKKS)
    parms.set_poly_modulus_degree(8192)
    parms.set_coeff_modulus(seal.CoeffModulus.Create(8192, [60, 40, 40, 60]))
    return seal.SEALContext(parms, True, seal.SEC_LEVEL_TYPE.TC128)


def cifrar_lista(encryptor, encoder, datos, scale):
    pt = seal.Plaintext()
    encoder.encode(datos, scale, pt)
    ct = seal.Ciphertext()
    encryptor.encrypt(pt, ct)
    return ct


def serializar_ct(ct):
    """Guarda ct en fichero temporal y devuelve los bytes (formato SEAL nativo)."""
    fd, path = tempfile.mkstemp(suffix=".ct")
    os.close(fd)
    ct.save(path)
    with open(path, "rb") as f:
        data = f.read()
    os.unlink(path)
    return data


def deserializar_ct(context, data):
    """Carga ct desde bytes usando fichero temporal."""
    fd, path = tempfile.mkstemp(suffix=".ct")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(data)
    ct = seal.Ciphertext()
    ct.load(context, path)
    os.unlink(path)
    return ct


# ══════════════════════════════════════════════
#  Socket helpers
# ══════════════════════════════════════════════

def enviar_bloque(sock, data: bytes):
    """Envía uint64_t(tamaño) + datos  (little-endian)."""
    sock.sendall(struct.pack('<Q', len(data)))
    sock.sendall(data)


def recibir_bloque(sock) -> bytes:
    """Recibe uint64_t(tamaño) + datos."""
    raw  = _recv_exacto(sock, 8)
    size = struct.unpack('<Q', raw)[0]
    return _recv_exacto(sock, size)


def _recv_exacto(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada por el servidor")
        buf.extend(chunk)
    return bytes(buf)


# ══════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════

def main():
    # ── Datos de entrada ──────────────────────
    lista1    = [10.0, 20.0, 30.0, 60.2, 40.2]
    lista2    = [4.0,  6.0,  8.0,  10.0, 20.4]
    operacion = "media"   # "media" → promedio,  "suma" → suma directa

    print("=" * 45)
    print(f"  Lista 1   : {lista1}")
    print(f"  Lista 2   : {lista2}")
    print(f"  Operación : {operacion}")
    print("=" * 45)

    # ── Configurar SEAL ───────────────────────
    context   = crear_contexto()
    keygen    = seal.KeyGenerator(context)
    pk        = seal.PublicKey()
    keygen.create_public_key(pk)
    sk        = keygen.secret_key()
    encryptor = seal.Encryptor(context, pk)
    decryptor = seal.Decryptor(context, sk)
    encoder   = seal.CKKSEncoder(context)
    scale     = 2 ** 40

    # ── Cifrar las listas ─────────────────────
    ct1    = cifrar_lista(encryptor, encoder, lista1, scale)
    ct2    = cifrar_lista(encryptor, encoder, lista2, scale)
    bytes1 = serializar_ct(ct1)
    bytes2 = serializar_ct(ct2)

    print(f"\n  ct1 cifrado : {len(bytes1):,} bytes")
    print(f"  ct2 cifrado : {len(bytes2):,} bytes")
    print(f"\n  Conectando a {HOST}:{PORT}...")

    # ── Enviar al servidor WSL ────────────────
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("  Conectado. Enviando datos cifrados...\n")

        enviar_bloque(s, operacion.encode("utf-8"))  # 1. comando
        enviar_bloque(s, bytes1)                     # 2. ct1
        enviar_bloque(s, bytes2)                     # 3. ct2

        resultado_bytes = recibir_bloque(s)          # 4. resultado

    print(f"  Resultado cifrado recibido ({len(resultado_bytes):,} bytes)")

    # ── Descifrar (solo el cliente tiene la clave privada) ──
    result_ct = deserializar_ct(context, resultado_bytes)
    result_pt = seal.Plaintext()
    decryptor.decrypt(result_ct, result_pt)


    resultado = encoder.decode_double(result_pt)
    resultado = resultado[:len(lista1)]

    # ── Mostrar ───────────────────────────────
    print("\n" + "=" * 45)
    print(f"  Resultado de '{operacion}' (descifrado en cliente):")
    for i, v in enumerate(resultado):
        esperado = (lista1[i] + lista2[i]) / (2 if operacion == "media" else 1)
        print(f"    [{i}]  {v:10.4f}   (esperado: {esperado:.4f})")
    print("=" * 45)


if __name__ == "__main__":
    main()