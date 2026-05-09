"""
Gestor de configuración con clave maestra.
Centraliza todas las claves sensibles y las desencripta una sola vez al iniciar.
"""

import os
import json
import json
import logging
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


class ConfigManager:
    """Gestor centralizado de configuración sensible."""
    
    def __init__(self):
        self.master_key = None
        self.config_data = {}
        self.config_dir = Path("./config")
        self.salt_file = self.config_dir / "salt.bin"
        
    def setup_master_password(self, password=None):
        """
        Configura o valida la contraseña maestra.
        Si no existe, crea los archivos encriptados.
        """
        if password is None:
            password = getpass.getpass(
                "🔐 Introduce tu contraseña maestra para desencriptar la configuración: "
            )
        
        # Derivar la clave maestra usando PBKDF2
        if self.salt_file.exists():
            with open(self.salt_file, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = kdf.derive(password.encode())
        logging.info("✓ Clave maestra derivada correctamente.")
        
        # Cargar o crear archivos encriptados
        self._load_or_encrypt_configs()
    
    def _load_or_encrypt_configs(self):
        """Carga archivos desencriptados o los encripta si no existen."""
        config_files = {
            "search_secret": "./config/search_secret.key",
            "client_secret": "./config/client_secret.json",
            "token_store": "./config/token_store.json",
            "ac_password": "./config/AC.txt",
        }
        
        for key, filepath in config_files.items():
            encrypted_path = f"{filepath}.encrypted"
            
            # Si existe la versión encriptada, desencriptarla
            if os.path.exists(encrypted_path):
                self.config_data[key] = self._decrypt_file(encrypted_path)
                logging.info(f"✓ {key} desencriptado desde {encrypted_path}")
            # Si existe el original sin encriptar, encriptarlo
            elif os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    content = f.read()
                self._encrypt_file(filepath, encrypted_path, content)
                self.config_data[key] = content
                logging.info(f"✓ {key} encriptado y guardado en {encrypted_path}")
                # Opcional: eliminar archivo original
                # os.remove(filepath)
    
    def _encrypt_file(self, source_path, dest_path, data):
        """Encripta datos usando AES-GCM."""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Guardar: IV (12 bytes) + TAG (16 bytes) + CIPHERTEXT
        with open(dest_path, "wb") as f:
            f.write(iv + tag + ciphertext)
        logging.debug(f"Archivo encriptado: {dest_path}")
    
    def _decrypt_file(self, encrypted_path):
        """Desencripta archivos con AES-GCM."""
        with open(encrypted_path, "rb") as f:
            data = f.read()
        
        # Extraer IV (12 bytes), TAG (16 bytes), CIPHERTEXT (resto)
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def get_search_secret(self):
        """Obtiene la clave secreta para búsquedas."""
        if "search_secret" not in self.config_data:
            # Si no existe, generarla
            secret = os.urandom(32)
            self.config_data["search_secret"] = secret
            return secret
        return self.config_data["search_secret"]
    
    def get_client_secret(self):
        """Obtiene credenciales OAuth de Google."""
        if "client_secret" not in self.config_data:
            return None
        try:
            return json.loads(self.config_data["client_secret"].decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            logging.error("Error desencriptando client_secret.json")
            return None
    
    def get_token_store(self):
        """Obtiene tokens OAuth guardados."""
        if "token_store" not in self.config_data:
            return None
        try:
            return json.loads(self.config_data["token_store"].decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
    
    def get_ac_password(self):
        """Obtiene la contraseña de AC."""
        if "ac_password" not in self.config_data:
            return None
        try:
            content = self.config_data["ac_password"].decode()
            # Extraer primera línea después de ':'
            for line in content.split('\n'):
                if 'Contraseña para firmas' in line:
                    continue
                if ':' in line:
                    return line.split(':')[1].strip()
        except (UnicodeDecodeError, IndexError):
            logging.error("Error leyendo contraseña de AC")
        return None
    
    def save_token_store(self, token_data):
        """Guarda tokens OAuth desencriptados."""
        encrypted_path = "./config/token_store.json.encrypted"
        data_bytes = json.dumps(token_data, indent=2).encode()
        self.config_data["token_store"] = data_bytes
        self._encrypt_file("./config/token_store.json", encrypted_path, data_bytes)
        logging.info("✓ Token store guardado y encriptado.")
    
    def save_search_secret(self, secret):
        """Guarda la clave secreta de búsqueda."""
        encrypted_path = "./config/search_secret.key.encrypted"
        self.config_data["search_secret"] = secret
        self._encrypt_file("./config/search_secret.key", encrypted_path, secret)
        logging.info("✓ Search secret guardado y encriptado.")


# Instancia global
_config_manager = None

def get_config_manager():
    """Obtiene la instancia global del gestor de configuración."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager

def initialize_config(password=None):
    """Inicializa el gestor de configuración (se llama una sola vez al iniciar)."""
    manager = get_config_manager()
    manager.setup_master_password(password)
    return manager
