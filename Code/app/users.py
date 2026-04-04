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
                DNI INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                first_surname TEXT,
                second_surname TEXT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT "client",
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

    def add_user(self, DNI, name, first_surname, second_surname, email, password, salt, private_key):
        # Añadir nuevo admin a la base de datos
        DNI_shorten = self.split_DNI(DNI)
        if DNI_shorten == False:
            return False
        else:
            try:
                self.cursor.execute(
                    "INSERT INTO users (DNI, name, first_surname, second_surname, email, password, salt, private_key) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?)",
                    (DNI_shorten, name, first_surname, second_surname, email, password, salt, private_key))
                self.connection.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def check_user(self, DNI_or_email_or_name):
        DNI = self.split_DNI(DNI_or_email_or_name)
        if DNI != False:
            user = self.cursor.execute(
            "SELECT * FROM users WHERE DNI=?",
            (DNI,)).fetchone()

        else:    
            user = self.cursor.execute(
                "SELECT * FROM users WHERE email=? OR name=?",
                (DNI_or_email_or_name, DNI_or_email_or_name.upper())
            ).fetchone()

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

    def update_certificate(self, name, certificate):
        # Actualizar certificado
        self.cursor.execute("UPDATE users SET certificate=? WHERE name=?", (certificate, name))
        self.connection.commit()


if __name__ == "__main__":
    DNI = sys.argv[1]
    certificate = sys.argv[2]
    users = Users(db_name="../db/users.db")
    users.update_certificate(DNI, certificate)