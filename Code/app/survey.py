import sqlite3
from datetime import datetime

class Survey:
    def __init__(self, db_name="./db/survey.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS survey (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                creator_id INTEGER NOT NULL,
                title VARCHAR(200) NOT NULL,
                is_public CHAR(1) DEFAULT 'y' CHECK(is_public IN ('y','n')),
                start_at TEXT,
                end_at TEXT,
                created_at TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                FOREIGN KEY (creator_id) REFERENCES user(id) ON DELETE CASCADE)''')
        self.connection.commit()
    
    def add_survey(self, creator_id, title, start_at, end_at, is_public='y'):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO survey (creator_id, title, is_public, start_at, end_at, created_at, last_modified) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (creator_id, title, is_public, start_at, end_at, now, now))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False
        
    def get_survey(self, survey_id):
        return self.cursor.execute("SELECT * FROM survey WHERE id = ?", (survey_id,)).fetchone()

    # PARA ADMIN
    def list_surveys(self):
        return self.cursor.execute("SELECT * FROM survey").fetchall()
    
    def list_surveys_creator(self, user):
        return self.cursor.execute("SELECT * FROM survey WHERE creator_id = ?", (user,)).fetchall()
    
    def list_surveys_admin(self, admin):
        return self.cursor.execute("SELECT * FROM survey WHERE admin = ?", (admin,)).fetchall()
        



class SurveyAdmins:
    def __init__(self, db_name="./db/survey.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS survey_admins (
                survey_id INTEGER NOT NULL,
                user_id   INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE)''')
        self.connection.commit()

    def add_admin(self, survey_id, user_id):
        try:
            self.cursor.execute(
                "INSERT INTO survey_admins (survey_id, user_id) VALUES (?, ?)",
                (survey_id, user_id))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_admin(self, survey_id, user_id):
        self.cursor.execute(
            "DELETE FROM survey_admins WHERE survey_id = ? AND user_id = ?",
            (survey_id, user_id))
        self.connection.commit()

    def list_admins(self, survey_id):
        return self.cursor.execute(
            "SELECT user_id FROM survey_admins WHERE survey_id = ?",
            (survey_id,)).fetchall()

    def is_admin(self, survey_id, user_id):
        result = self.cursor.execute(
            "SELECT 1 FROM survey_admins WHERE survey_id = ? AND user_id = ?",
            (survey_id, user_id)).fetchone()
        return result is not None


class SurveyWhitelist:
    def __init__(self, db_name="./db/survey.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS survey_whitelist (
                survey_id INTEGER NOT NULL,
                user_id   INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE)''')
        self.connection.commit()

    def add_to_whitelist(self, survey_id, user_id):
        try:
            self.cursor.execute(
                "INSERT INTO survey_whitelist (survey_id, user_id) VALUES (?, ?)",
                (survey_id, user_id))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_from_whitelist(self, survey_id, user_id):
        self.cursor.execute(
            "DELETE FROM survey_whitelist WHERE survey_id = ? AND user_id = ?",
            (survey_id, user_id))
        self.connection.commit()

    def list_whitelist(self, survey_id):
        return self.cursor.execute(
            "SELECT user_id FROM survey_whitelist WHERE survey_id = ?",
            (survey_id,)).fetchall()

    def is_allowed(self, survey_id, user_id):
        result = self.cursor.execute(
            "SELECT 1 FROM survey_whitelist WHERE survey_id = ? AND user_id = ?",
            (survey_id, user_id)).fetchone()
        return result is not None