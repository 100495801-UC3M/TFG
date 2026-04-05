import sys
import sqlite3

class Users:
    def __init__(self, db_name="./db/users.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                DNI TEXT NOT NULL UNIQUE,
                DNI_search TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE,
                first_surname TEXT,
                second_surname TEXT,
                email TEXT NOT NULL UNIQUE,
                email_search TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT "client",
                created_at FLOAT,
                salt TEXT NOT NULL,
                private_key TEXT,
                certificate TEXT)''')
        self.connection.commit()

    def split_DNI(self, DNI):
        if len(DNI) != 9:
            return False
        
        if not DNI[0:8].isdigit():
            return False
        
        return (int(DNI[0:8]))


    def add_user(self, DNI, DNI_search, name, first_surname, second_surname, 
                email, email_search, password, created_at, salt, private_key):
        try:
            self.cursor.execute(
                """INSERT INTO users 
                (DNI, DNI_search, name, first_surname, second_surname,
                    email, email_search, password, created_at, salt, private_key) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (DNI, DNI_search, name, first_surname, second_surname,
                email, email_search, password, created_at, salt, private_key))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    # identifier es el email o dni encriptado si fuese tal, nombre no encriptado
    # type = DNI, email o name
    def check_user(self, identifier, type):
        if type == "name":
            user = self.cursor.execute(
                    "SELECT * FROM users WHERE name=?", (identifier.upper(),)).fetchone()
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



if __name__ == "__main__":
    name = sys.argv[1]
    certificate = sys.argv[2]
    users = Users(db_name="../db/users.db")
    users.update_certificate(name, certificate)