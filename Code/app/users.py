import sqlite3
from datetime import datetime, timedelta


class Users:
    def __init__(self, db_name="./db/users.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_tables()

    def create_tables(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                DNI             TEXT NOT NULL UNIQUE,
                DNI_search      TEXT NOT NULL UNIQUE,
                name            VARCHAR(50) NOT NULL UNIQUE,
                email           TEXT NOT NULL UNIQUE,
                email_search    TEXT NOT NULL UNIQUE,
                password        TEXT NOT NULL,
                role            TEXT DEFAULT "client",
                created_at      TEXT NOT NULL,
                salt            TEXT NOT NULL,
                private_key     TEXT,
                certificate     TEXT);
        ''')
        self.connection.commit()

    def split_DNI(self, DNI):
        if len(DNI) != 9:
            return False
        
        if not DNI[0:8].isdigit():
            return False
        
        return (int(DNI[0:8]))


    def add_user(self, DNI, DNI_search, name, email, email_search,
                 password, salt, private_key):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                """INSERT INTO users 
                (DNI, DNI_search, name, email, email_search,
                password, created_at, salt, private_key) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (DNI, DNI_search, name, email, email_search,
                 password, now, salt, private_key))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    # identifier es el email o dni encriptado si fuese tal, nombre no encriptado
    # type = DNI, email o name
    def check_user(self, identifier, type):
        if type == "name":
            user = self.cursor.execute(
                "SELECT * FROM users WHERE name=?", (identifier.lower(),)).fetchone()
        elif type == "DNI":
            user = self.cursor.execute(
                    "SELECT * FROM users WHERE DNI=?", (identifier,)).fetchone()
        else:
            user = self.cursor.execute(
                "SELECT * FROM users WHERE email=?", (identifier,)).fetchone()

        if user is None:
            return False
        
        return dict(user)

    def list_users(self):
        # Devolver lista de todos los usuarios
        return self.cursor.execute("SELECT * FROM users").fetchall()

    def update_password(self, name, password, private_key):
        # Cambiar la contraseña
        self.cursor.execute("UPDATE users SET password=?, private_key=? WHERE name=?",
                            (password, private_key, name))
        self.connection.commit()

    def remove_user(self, name):
        # Eliminar Usuario
        self.cursor.execute("DELETE FROM users WHERE name=?", (name,))
        self.connection.commit()

    def promote_user(self, name):
        # Ascender a admin a un usuario
        self.cursor.execute("UPDATE users SET role='admin' WHERE name=?", (name,))
        self.connection.commit()

    def update_certificate(self, identifier, certificate):
        if type(identifier) == int:
            self.cursor.execute("UPDATE users SET certificate=? WHERE DNI=?",
                                (certificate, identifier))
        else:
            self.cursor.execute("UPDATE users SET certificate=? WHERE name=? OR email=?",
                                (certificate, identifier, identifier))
        self.connection.commit()

    def update_password_reset(self, name, password, private_key):
        self.cursor.execute(
            "UPDATE users SET password=?, private_key=?, certificate='' WHERE name=?",
            (password, private_key, name)
        )
        self.connection.commit()
    
    def identifier_type(self, identifier):
        if self.split_DNI(identifier) != False:
            return "DNI"
        elif "@" in identifier:
            return "email"
        else:
            return "name"
        
    # Función para cambiar la base de datos ejecutando en este .py
    def changes_to_database(self, survey_id):
        self.cursor.execute("DELETE FROM answer WHERE submitted_answer_id IN "
            "(SELECT id FROM submitted_answer WHERE survey_id = ?)", (survey_id,))
        self.cursor.execute("DELETE FROM submitted_answer WHERE survey_id = ?", (survey_id,))
        self.connection.commit()
        print("OK")

class Session_private_key:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()
    
    def create_table(self):
        """Crea la tabla de session_private_key si no existe."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_private_key (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL UNIQUE,
                private_key     TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                expires_at      TEXT NOT NULL)''')
        self.connection.commit()

    def get_session_private_key(self, session_id):
        """Obtiene la clave privada de un session_id."""
        result = self.cursor.execute(
            "SELECT private_key FROM session_private_key WHERE session_id = ? AND expires_at > ?",
            (session_id, datetime.now().isoformat())
        ).fetchone()
        if result:
            return result["private_key"]
        return None

    def delete_session_private_key(self, session_id):
        """Elimina la clave privada de un session_id."""
        self.cursor.execute("DELETE FROM session_private_key WHERE session_id = ?", (session_id,))
        self.connection.commit()

    def cleanup_expired_sessions(self):
        """Limpia sesiones expiradas."""
        now = datetime.now().isoformat()
        self.cursor.execute("DELETE FROM session_private_key WHERE expires_at < ?", (now,))
        self.connection.commit()
        
    def save_session_private_key(self, session_id, private_key):
        """Guarda la clave privada asociada a un session_id."""
        now = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(hours=1)).isoformat()  # Expira en 1 hora
        self.cursor.execute(
            "INSERT OR REPLACE INTO session_private_key (session_id, private_key, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (session_id, private_key, now, expires_at)
        )
        self.connection.commit()


class Registration_token:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()
    
    def create_table(self):
        """Crea la tabla de registration_token si no existe."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS registration_token (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                token           TEXT NOT NULL UNIQUE,
                data            TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                expires_at      TEXT NOT NULL)''')
        self.connection.commit()

    def save_registration_token(self, token, data, expires_at):
        """Guarda un token de registro con sus datos en BD."""
        import json
        data_json = json.dumps(data)
        now = datetime.now().isoformat()
        self.cursor.execute(
            "INSERT INTO registration_token (token, data, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, data_json, now, expires_at)
        )
        self.connection.commit()

    def get_registration_token(self, token):
        """Obtiene los datos de un token de registro."""
        import json
        result = self.cursor.execute(
            "SELECT data, expires_at FROM registration_token WHERE token = ?",
            (token,)
        ).fetchone()
        if result:
            return {
                "data": json.loads(result["data"]),
                "expires_at": result["expires_at"]
            }
        return None

    def delete_registration_token(self, token):
        """Elimina un token de registro."""
        self.cursor.execute("DELETE FROM registration_token WHERE token = ?", (token,))
        self.connection.commit()

    def cleanup_expired_tokens(self):
        """Limpia tokens de registro expirados."""
        now = datetime.now().isoformat()
        self.cursor.execute("DELETE FROM registration_token WHERE expires_at < ?", (now,))
        self.connection.commit()

if __name__ == "__main__":
    import sys
    users = Users(db_name="../db/users.db")
    if len(sys.argv) == 3:
        identifier = sys.argv[1]
        certificate = sys.argv[2]
        users.update_certificate(identifier, certificate)
        print("Cert cambiado")
    if len(sys.argv) == 2:
        user = sys.argv[1]
        users.promote_user(user)
        print("Usuario promovido")
        