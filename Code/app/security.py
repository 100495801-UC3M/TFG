import os
import re
import logging
import base64
import requests # para enviar correos
import time # para enviar correos
import json # para enviar correos
from email.header import Header # para enviar correos
from email.utils import formataddr # para enviar correos
import hmac as hmac_module
import hashlib

from app.users import Users
from datetime import datetime
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


# Revisar si el DNI es válido.
def DNI_valid(DNI):
    letter = ("T", "R", "W", "A", "G", "M", "Y", "F", "P", "D", "X", "B", "N", "J", "Z", "S", "Q", "V", "H", "L", "C", "K", "E")
    if len(DNI) != 9:
        return (False, "El tamaño del DNI no es el correcto.")
    if not DNI[0:8].isdigit() or not DNI[-1].isalpha() or DNI[-1] != letter[int(DNI[0:8]) % 23]:
        return (False, "El DNI no es válido.")
    return (True, "")

def check_password(password):
    # Revisar si la contraseña cumple con los requisitos mínimos
    if " " in password:
        return False

    if len(password) < 6:
        return False

    if (re.search(r"[A-Z]", password) and  # Al menos una letra mayúscula
            re.search(r"[a-z]", password) and  # Al menos una letra minúscula
            re.search(r"\d", password, re.ASCII) and  # Al menos un número
            re.search(r"[$!%*?&_¿@#=-]", password)):  # Al menos un carácter especial
        return True
    else:
        return False


def generate_salt_aes(procces, number):
    # Generar salt o una clave aes
    key = os.urandom(number)
    if procces == "salt":
        logging.info(f"Salt generado: {key.hex()}, Longitud de clave: {number * 8} bits")
    else:
        logging.info(f"Salt generado: {key.hex()}, Longitud de clave: {number * 8} bits")
    return key


def hash(password, salt):
    # Hasear la contrasña usando el hash
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=100000, backend=default_backend())
    password_hash = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    logging.info(f"Algoritmo: PBKDF2-HMAC-SHA256, Longitud de clave: 32 "
                    f"bytes, Salt: {base64.urlsafe_b64encode(salt)}, "
                    f"Contraseña_Hash: {password_hash}")
    return password_hash

def verify_password(stored_password, salt, provided_password):
    # Crear el KDF (Key Derivation Function) con los mismos parámetros que el hash original
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        # Verificar si el hash derivado coincide con el almacenado
        derived_hash = kdf.derive(provided_password.encode())
        return base64.urlsafe_b64encode(derived_hash) == stored_password
    except Exception:
        return False


def generate_keys():
    # Generar las clave privada y pública
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_private_key(private_key, password, salt):
    # Encriptar la clave privada
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    private_encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )

    return private_encrypted_key


def serialize_private_key(private_key):
    # Serializar la clave privada
    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return serialized_private_key.decode("utf-8")


def decrypt_private_key(encrypted_private_key, password, salt):
    # Derivar la clave para descifrar
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Cargar y descifrar la clave privada
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=key,
        backend=default_backend()
    )
    return private_key


def deserialize_private_key(serialized_private_key):
    # Deserializar la clave privada
    private_key = serialization.load_pem_private_key(
        serialized_private_key.encode("utf-8"),
        password=None
    )
    return private_key


def encrypt_aes_message(message, aes_key):
    # Cifrar el mensaje con la clave aes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
    logging.info(f"Mensaje cifrado con AES: {encrypted_message.hex()}")
    return encrypted_message


def decrypt_message(mensaje_cifrado, clave_aes):
    # Descifrar el mensaje con la clave aes
    iv = mensaje_cifrado[:16]
    ciphertext = mensaje_cifrado[16:]

    cipher = Cipher(algorithms.AES(clave_aes), modes.CFB(iv))
    decryptor = cipher.decryptor()

    mensaje_descifrado = decryptor.update(ciphertext) + decryptor.finalize()
    logging.info(f"Mensaje descifrado: {mensaje_descifrado.decode('utf-8')}")
    return mensaje_descifrado.decode("utf-8")


def generate_hmac(aes_key, encrypted_message):
    # Generar el HMAC usando la clave AES y el mensaje cifrado
    h = HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)
    hmac_tag = h.finalize()
    logging.info(f"HMAC generado: {hmac_tag.hex()}")
    return hmac_tag


def verify_hmac(aes_key, encrypted_message, hmac_label_received):
    # Generar un nuevo HMAC usando la misma clave AES y verificar si el HMAC coincide con el recibido
    h = HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)

    try:
        h.verify(hmac_label_received)
        logging.info("HMAC verificado correctamente. El mensaje es auténtico.")
        return True
    except InvalidSignature:
        logging.error("HMAC incorrecto. El mensaje ha sido alterado o no es auténtico.")
        return False


def encrypt_aes_rsa_key(aes_key, public_key):
    # Cifrar la clave AES usando la clave pública
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(f"Clave AES cifrada con RSA: {encrypted_aes_key.hex()}")
    return encrypted_aes_key


def decrypt_aes_rsa_key(encrypted_aes_key, private_key):
    # Descifrar la clave AES usando la clave privada
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(f"Clave AES descifrada con RSA: {aes_key.hex()}")
    return aes_key


def check_messages(conversations, username, username_public_key, username_private_key):
    # Verificar si los mensajes se puden descifrar con la clave privada y devolver los que si se han podido
    good_messages = []

    # Conseguir por cada mensaje la clave AES descifrada y la clave pública de quien ha enviado el mensaje
    for message in conversations:
        if message["sender"] == username:
            try:
                aes = decrypt_aes_rsa_key(message["aes_key_sender"], username_private_key)
                sender_public_key = username_public_key
            except:
                return "error"
        else:
            try:
                aes = decrypt_aes_rsa_key(message["aes_key_receiver"], username_private_key)
                users_db = Users(db_name="./db/users.db")
                user = users_db.check_user(message["sender"])

                route = user["certificate"]

                if route == "" or route is None:
                    return "error"
                else:
                    sender_public_key = get_public_key_from_certificate(route)
            except:
                
                return "error"

        # Verificar el mensaje tanto por la firma con la clave pública como por el hmac. Proporciona integridad, autenticidad y confidencialidad
        if verify_message(message["text"], message["hmac"], message["signature"], sender_public_key):
            if verify_hmac(aes, message["text"], message["hmac"]):
                message_decrypted = decrypt_message(message["text"], aes)
                good_messages.append([message["id"], message["sender"], message_decrypted, message["datehour"]])
                logging.info(f"La firma del mensaje ha sido verificada correctamente")

    return good_messages


def create_request(username, public_key, private_key):
    # Crear una solicitud de certificado
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username)
    ])).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False
    )

    csr = csr.sign(private_key, hashes.SHA256())

    route = f"AC/solicitudes/{username}.pem"

    with open(route, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    logging.info(
        f"Solicitud de certificado creada para {username}. "
        f"Clave pública: RSA, Longitud: {public_key.key_size} bits. "
        f"Algoritmo de firma del CSR: SHA256."
    )


def open_certificate(cert_path):
    # Función para abrir un certificado y leer sus datos
    cert_path = cert_path.strip()
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    logging.info("Certificado %s abierto y leido", cert_path)
    return x509.load_pem_x509_certificate(cert_data, default_backend())



def verify_certificate(cert_path):
    # Verificar la validez de un certificado
    cert_path = cert_path.strip()
    cert_path = "AC/nuevoscerts/" + cert_path + ".pem"
    user_cert = open_certificate(cert_path)

    if verify_signature(user_cert) and verify_validity(user_cert):
        logging.info(f"Certificado válido y verificado correctamente: {cert_path}. Algoritmo de firma: {user_cert.signature_hash_algorithm.name}")
        return True
    logging.warning("Certificado no válido ya sea por firma incorrecta o por caducidad: %s", cert_path)
    return False


def verify_signature(cert):
    # Veificar la firma del certificado
    ca_cert = open_certificate("AC/ac1cert.pem")

    try:
        ca_cert.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
        logging.info(f"Firma del certificado verificada correctamente. Clave pública de la CA: {ca_cert.public_key().key_size} bits.")
        return True
    except InvalidSignature:
        logging.error("La firma del certificado es incorrecta.")
        return False
    

def verify_validity(cert):
    # Comprobar si el certificado está dentro de su periodo de validez
    current_time = datetime.now()
    if cert.not_valid_before <= current_time <= cert.not_valid_after:
        logging.info("Certificado dentro del periodo de validez.")
        return True
    logging.warning("Certificado fuera del periodo de validez.")
    return False


def get_public_key_from_certificate(cert_path):
    # Obtener la clave pública de un certificado
    cert_path = cert_path.strip()
    cert_path = "./AC/nuevoscerts/" + cert_path + ".pem"
    cert = open_certificate(cert_path)

    logging.info("Clave pública obtenida del certificado: Longitud %d bits", cert.public_key().key_size)
    return cert.public_key()


def get_public_key_from_request(request_path):
    # Obtener la clave pública de una solicitud de certificado
    with open(request_path, "rb") as f:
        csr_data  = f.read()
    csr = x509.load_pem_x509_csr(csr_data , default_backend())
    
    logging.info("Clave pública obtenida: Longitud %d bits", csr.public_key().key_size)
    return csr.public_key()


def sign_message(encryped_message, hmac, sender_private_key):
    # Firmar el mensaje con la clave privada del emisor
    message = encryped_message + hmac 
    signature = sender_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    #NOTA: El log aparece ANTES de la verificación de todos los mensajes, por lo que aunque esté en la terminal,
    # puede que no lo encuentres rápidamente. Recomendable usar CNTRL + F y buscar "chacha256" en la terminal.
    logging.info(f"La firma del mensaje: {message.hex()} ha sido creada con ChaCha256")
    return signature


def verify_message(encryped_message, hmac, signature, public_key):
    # Verificar la firma del mensaje
    message = encryped_message + hmac 
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        
        logging.info("Firma verificada correctamente. Algoritmo de hash: SHA256, Padding: PSS con MGF1.")
        return True
    except InvalidSignature:
        logging.error("La firma es inválida. El mensaje puede haber sido alterado.")
        return False
    except Exception as e:
        logging.error(f"Error inesperado durante la verificación: {str(e)}")
        return False


def send_email_gmail_api(from_email: str, to_email: str, subject: str, body: str):
    to_email = to_email.strip().strip('"')
    subject_encoded = Header(subject, "utf-8").encode()

    # Separar nombre y dirección, codificar solo el nombre
    # from_email viene como: 'AGULE - Recuperacion <mariohidtfg@gmail.com>'
    match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>$', from_email.strip())
    if match:
        name = match.group(1).strip()
        address = match.group(2).strip()
        from_encoded = formataddr((Header(name, "utf-8").encode(), address))
    else:
        from_encoded = from_email

    message_lines = [
        f"From: {from_encoded}",
        f"To: {to_email}",
        f"Subject: {subject_encoded}",
        "Content-Type: text/plain; charset=utf-8",
        "",
        body
    ]
    message_text = "\r\n".join(message_lines)

    # 2. Convertir a base64 URL-safe
    message_bytes = message_text.encode("utf-8")
    message_base64 = base64.urlsafe_b64encode(message_bytes).decode("utf-8")

    # 3. Construir payload
    payload = {"raw": message_base64}

    # 4. Leer token_data de token_store.json
    with open("./config/token_store.json") as f:
        token_data = json.load(f)
    
    # Verificar expiración y refrescar si procede
    expires_at = token_data.get("expires_at")
    if expires_at and time.time() >= expires_at:
        new_token = refresh_access_token()
        token_data.update(new_token)
        # Guardar el token actualizado en token_store.json
        with open("./config/token_store.json", "w") as f:
            json.dump(token_data, f)
    
    access_token = token_data.get("access_token")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # 5. Enviar request y reintentar una vez si recibimos 401 (token expirado)
    response = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers=headers,
        json=payload
    )

    if response.status_code == 401:
        # Refrescar si da error
        new_token = refresh_access_token()
        token_data.update(new_token)
        # Guardar el token actualizado en token_store.json
        with open("./config/token_store.json", "w") as f:
            json.dump(token_data, f)
        access_token = token_data.get("access_token")

        headers["Authorization"] = f"Bearer {access_token}"
        # Reintentar
        response = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers=headers,
            json=payload
        )

    return response.status_code, response.text

def refresh_access_token():

    # client_id y client_secret → client_secret.json
    with open("./config/client_secret.json") as f:
        config = json.load(f)["web"]

    # refresh_token → token_store.json
    with open("./config/token_store.json") as f:
        token_store = json.load(f)

    url = "https://oauth2.googleapis.com/token"

    data = {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "refresh_token": token_store["refresh_token"],
        "grant_type": "refresh_token"
    }

    response = requests.post(url, data=data)
    print(response.text)
    response.raise_for_status()

    token_data = response.json()

    return {
        "access_token": token_data["access_token"],
        "expires_at": time.time() + token_data["expires_in"]
    }

def load_search_secret():
    secret_path = "./config/search_secret.key"
    
    if os.path.exists(secret_path):
        with open(secret_path, "rb") as f:
            return f.read().strip()
    
    # Si no existe, generarla automáticamente y guardarla
    secret = os.urandom(32)
    os.makedirs("./config", exist_ok=True)
    with open(secret_path, "wb") as f:
        f.write(secret)
    logging.warning("search_secret.key generada automáticamente en config/")
    return secret

def make_search_index(value, SECRET_KEY):
    """Genera un índice ciego determinista para búsquedas."""
    value_normalized = value.strip().upper()
    tag = hmac_module.new(SECRET_KEY, value_normalized.encode(), hashlib.sha256).hexdigest()
    return tag

def encrypt_field(value, server_key):
    """Cifra un campo con AES-GCM para almacenamiento."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(server_key), modes.GCM(iv))
    enc = cipher.encryptor()
    ct = enc.update(value.encode()) + enc.finalize()
    # Guardar iv + tag + ciphertext en base64
    return base64.b64encode(iv + enc.tag + ct).decode()

def decrypt_field(encrypted, server_key) -> str:
    """Descifra un campo almacenado con encrypt_field."""
    raw = base64.b64decode(encrypted)
    iv, tag, ct = raw[:12], raw[12:28], raw[28:]
    cipher = Cipher(algorithms.AES(server_key), modes.GCM(iv, tag))
    dec = cipher.decryptor()
    return (dec.update(ct) + dec.finalize()).decode()