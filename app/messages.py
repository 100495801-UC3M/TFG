import sqlite3
from datetime import datetime


class Messages:
    def __init__(self, db_name="./db/messages.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                hmac TEXT NOT NULL,
                aes_key_sender TEXT NOT NULL,
                aes_key_receiver TEXT NOT NULL,
                datehour TEXT NOT NULL,
                signature TEXT NOT NULL)''')
        self.connection.commit()

    def send_message(self, sender, receiver, text, hmac, aes_key_sender, aes_key_receiver, signature):
        # Función para añadir un mensaje
        try:
            date = datetime.now().strftime("%H:%M:%S %d-%m-%Y")
            self.cursor.execute(
                "INSERT INTO messages (sender, receiver, text, hmac, aes_key_sender, aes_key_receiver, datehour, signature) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?)",
                (sender, receiver, text, hmac, aes_key_sender, aes_key_receiver, date, signature))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def conversations(self, user_logued, user_searched):
        # Cargar los mensajes entre el usuario actual y el destinatario
        conversations = self.cursor.execute(
        "SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) "
        "ORDER BY datehour ASC", 
        (user_logued, user_searched, user_searched, user_logued)
        ).fetchall()

        # Convertir a una lista de diccionarios
        conversations_list = [dict(row) for row in conversations]
        return conversations_list
    
    def get_message(self, id):
        # Recuperar un mensaje por su id
        return self.cursor.execute("SELECT * FROM messages WHERE id=?", (id,))
    
    def list_messages(self):
        # Devolver lista de todos los mensajes
        return self.cursor.execute("SELECT * FROM messages").fetchall()
    
    def list_conversations(self, username):
        # Devolver lista de todas las conversaciones del usuario
        return self.cursor.execute(
            """
            SELECT
                id,
                CASE 
                    WHEN sender = ? THEN receiver
                    ELSE sender
                END AS conversation_partner,
                text AS last_message,
                MAX(datehour) AS last_date
            FROM messages
            WHERE sender = ? OR receiver = ?
            GROUP BY conversation_partner
            ORDER BY last_date DESC
            """,
            (username, username, username)
        ).fetchall()
    
    def remove_messages(self, user):
        # Eliminar mensajes de un usuario
        self.cursor.execute("DELETE FROM messages WHERE sender=? OR receiver=?", (user, user))
        self.connection.commit()
