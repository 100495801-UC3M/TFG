"""
app/cppclient.py  —  Cliente SEAL (Python)
================================================
Comunica con servidor SEAL en WSL para operaciones homomorfas.
Solo encripta lista2 (nuevos datos); lista1 (estadísticas acumuladas) 
viene ya encriptada desde la BD.

Operaciones soportadas:
  "suma"  → resultado[i] = lista1_encriptada[i] + lista2_cifrada[i]
  "media" → resultado[i] = (lista1_encriptada[i] + lista2_cifrada[i]) / 2

Protocolo (little-endian uint64_t + bytes):
  Cliente → Servidor:
    1. uint64_t + bytes  → comando ("suma" o "media")
    2. uint64_t + bytes  → ciphertext 1 (encriptado, de BD)
    3. uint64_t + bytes  → ciphertext 2 (encriptado, lista2 nueva)
  Servidor → Cliente:
    4. uint64_t + bytes  → resultado cifrado

El servidor (servidor_seal) debe estar corriendo en WSL.
"""

import socket
import struct
import tempfile
import os
import base64
import logging
import tenseal.sealapi as seal


# Configuración de red
HOST = "127.0.0.1"
PORT = 8080


# SEAL helpers (funciones globales)

def _create_context():
    """Parámetros idénticos a los del servidor (servidor_seal.cpp)."""
    parms = seal.EncryptionParameters(seal.SCHEME_TYPE.CKKS)
    parms.set_poly_modulus_degree(8192)
    parms.set_coeff_modulus(seal.CoeffModulus.Create(8192, [60, 40, 40, 60]))
    return seal.SEALContext(parms, True, seal.SEC_LEVEL_TYPE.TC128)


def _encrypt_list(encryptor, encoder, data, scale):
    """Cifra una lista de floats."""
    pt = seal.Plaintext()
    encoder.encode(data, scale, pt)
    ct = seal.Ciphertext()
    encryptor.encrypt(pt, ct)
    return ct


def _serialize_ct(ct):
    """Serializa un ciphertext a bytes usando el formato nativo de SEAL."""
    fd, path = tempfile.mkstemp(suffix=".ct")
    os.close(fd)
    try:
        ct.save(path)
        with open(path, "rb") as f:
            data = f.read()
        return data
    finally:
        if os.path.exists(path):
            os.unlink(path)

# Socket helpers (funciones globales)

def _send_block(sock, bytes):
    """Envía uint64_t(tamaño) + datos (little-endian)."""
    sock.sendall(struct.pack('<Q', len(bytes)))
    sock.sendall(bytes)


def _recieve_block(sock) -> bytes:
    """Recibe uint64_t(tamaño) + datos."""
    size = struct.unpack('<Q', _exact_recv(sock, 8))[0]
    return _exact_recv(sock, size)


def _exact_recv(sock, number) -> bytes:
    """Recibe exactamente n bytes."""
    buf = bytearray()
    while len(buf) < number:
        chunk = sock.recv(number - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada por el servidor")
        buf.extend(chunk)
    return bytes(buf)


# Cliente SEAL

class Cliente:
    """
    Cliente SEAL para operaciones homomorfas con el servidor.
    
    Flujo:
    1. Recibe lista1_encrypted_base64 (de BD, puede ser None)
    2. Recibe lista2_plain (nuevos datos sin cifrar)
    3. Recibe operacion ("suma" o "media")
    4. Encripta SOLO lista2
    5. Deserializa lista1 (si no es None)
    6. Envía ambas al servidor
    7. Recibe resultado encriptado
    8. Retorna resultado en base64
    """
    
    def __init__(self):
        """Inicializa contexto SEAL y genera claves."""
        try:
            self.context = _create_context()
            keygen = seal.KeyGenerator(self.context)
            
            self.public_key = seal.PublicKey()
            keygen.create_public_key(self.public_key)
            self.secret_key = keygen.secret_key()
            
            self.encryptor = seal.Encryptor(self.context, self.public_key)
            self.decryptor = seal.Decryptor(self.context, self.secret_key)
            self.encoder = seal.CKKSEncoder(self.context)
            self.scale = 2 ** 40
            
            logging.info("Cliente SEAL inicializado correctamente")
        except Exception as e:
            logging.error(f"Error al inicializar Cliente SEAL: {e}")
            raise
    
    def compute_sum(self, list2_plain, list1_encrypted_base64=None):
        """
        Calcula suma homomórfica: resultado = lista1_encriptada + lista2_encriptada.
        
        Args:
            list2_plain: list[float] - nuevos datos sin cifrar
            list1_encrypted_base64: str base64 - estadísticas encriptadas de BD (puede ser None)
        
        Returns:
            str base64 - resultado encriptado, listo para guardar en BD
        """
        return self._execute_operation("suma", list2_plain, list1_encrypted_base64)
    
    def compute_average(self, votes, list2_plain, list1_encrypted_base64=None, ):
        """
        Calcula media homomórfica: resultado = (lista1_encriptada + lista2_encriptada) / votes.
        
        Args:
            votes: int - número total de votos (incluyendo el actual)
            list2_plain: list[float] - nuevos datos sin cifrar
            list1_encrypted_base64: str base64 - estadísticas encriptadas de BD (puede ser None)
        
        Returns:
            str base64 - resultado encriptado, listo para guardar en BD
        """
        return self._execute_operation("media", list2_plain, list1_encrypted_base64, votes)
    
    def _execute_operation(self, operation, list2_plain, list1_encrypted_base64, votes=None):
        """
        Ejecuta operación homomórfica.
        
        1. Si list1_encrypted_base64 es None, crea list1 de ceros y la encripta
        2. Si list1_encrypted_base64 no es None, la deserializa (ya encriptada)
        3. Encripta list2_plain
        4. Envía ambas al servidor
        5. Recibe resultado encriptado
        6. Retorna en base64
        """
        try:
            # Paso 1: Preparar lista1 (encriptada)
            if list1_encrypted_base64 is None:
                # Primera vez: encriptar ceros
                list1_cero = [0.0] * len(list2_plain)
                ct1 = _encrypt_list(self.encryptor, self.encoder, list1_cero, self.scale)
                bytes1 = _serialize_ct(ct1)
            else:
                # Deserializar desde base64
                try:
                    bytes1 = base64.b64decode(list1_encrypted_base64)
                except Exception as e:
                    logging.error(f"Error al decodificar lista1 base64: {e}")
                    return None
            
            # Paso 2: Encriptar lista2 (nuevos datos)
            ct2 = _encrypt_list(self.encryptor, self.encoder, list2_plain, self.scale)
            bytes2 = _serialize_ct(ct2)
            
            logging.debug(f"Lista1 cifrada: {len(bytes1):,} bytes")
            logging.debug(f"Lista2 cifrada: {len(bytes2):,} bytes")
            
            # Paso 3: Conectar al servidor y enviar
            result_bytes = None
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((HOST, PORT))
                    _send_block(s, operation.encode("utf-8"))  # comando
                    _send_block(s, bytes1)                     # ct1 (lista1)
                    _send_block(s, bytes2)                     # ct2 (lista2)
                    if operation == "media":
                        if not votes or votes == 0:
                            logging.error("votes es 0 o None, no se puede calcular la media")
                            return None
                        scalar = 1.0 / votes
                        scalar_bytes = struct.pack('<d', scalar)  # double little-endian
                        _send_block(s, scalar_bytes)
                    result_bytes = _recieve_block(s)          # resultado
                    
                logging.debug(f"Resultado recibido del servidor: {len(result_bytes):,} bytes")
            except socket.error as e:
                logging.error(f"Error de conexión con servidor SEAL: {e}")
                return None
            
            # Paso 4: Convertir a base64 y retornar
            result_base64 = base64.b64encode(result_bytes).decode('utf-8')
            logging.info(f"Operación '{operation}' completada exitosamente")
            
            return result_base64
            
        except Exception as e:
            logging.error(f"Error en _execute_operation: {e}")
            return None


# Main (para testing)

def main():
    """Test de la clase Cliente."""
    logging.basicConfig(level=logging.DEBUG)
    
    lista1    = [10.0, 20.0, 30.0, 60.2, 40.2]
    lista2    = [4.0,  6.0,  8.0,  10.0, 20.4]
    
    cliente = Cliente()
    
    # Test 1: suma
    print("\n=== Test SUMA ===")
    resultado_suma_b64 = cliente.compute_sum(lista2, None)
    if resultado_suma_b64:
        print(f"Suma completada. Resultado (base64): {resultado_suma_b64[:50]}...")
    
    # Test 2: media
    print("\n=== Test MEDIA ===")
    resultado_media_b64 = cliente.compute_average(lista2, None)
    if resultado_media_b64:
        print(f"Media completada. Resultado (base64): {resultado_media_b64[:50]}...")


if __name__ == "__main__":
    main()