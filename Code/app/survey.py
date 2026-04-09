import sqlite3
from datetime import datetime

class Survey:
    def __init__(self, db_name="./db/survey.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS survey (
                id INTEGER      PRIMARY KEY AUTOINCREMENT,
                creator_id      INTEGER NOT NULL,
                title           VARCHAR(200) NOT NULL,
                is_public       CHAR(1) DEFAULT 'y' CHECK(is_public IN ('y','n')),
                start_at        TEXT,
                end_at          TEXT,
                created_at      TEXT NOT NULL,
                last_modified   TEXT NOT NULL,
                FOREIGN KEY (creator_id) REFERENCES user(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS survey_admins (
                survey_id       INTEGER NOT NULL,
                user_id         INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS survey_whitelist (
                survey_id       INTEGER NOT NULL,
                user_id         INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER      PRIMARY KEY AUTOINCREMENT,
                survey_id       INTEGER NOT NULL,
                is_demographic  CHAR(1) DEFAULT 'n' CHECK(is_demographic IN ('y','n')),
                title           TEXT NOT NULL,
                type            CHAR(1) DEFAULT 't' CHECK(type IN ('t', 'n', 's', 'm')),
                position        INT DEFAULT 0,
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS question_options (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id     INTEGER NOT NULL,
                option_text     TEXT NOT NULL,
                position        INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE);
        ''')
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
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

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
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

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
    
class Questions:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def add_question(self, survey_id, is_demographic, title, type, position):
        try:
            self.cursor.execute(
                "INSERT INTO questions (survey_id, is_demographic, title, type, position) "
                "VALUES (?, ?, ?, ?, ?)",
                (survey_id, is_demographic, title, type, position))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        
    def remove_question(self, question_id):
        try:
            question = self.get_question(question_id)
            survey_id = question[survey_id]
            self.cursor.execute("DELETE FROM questions WHERE question_id = ?",(question_id,))
            self.connection.commit()
            self.reorder_positions(survey_id)
            return True
        except sqlite3.IntegrityError:
            return False
    
    def reorder_positions(self, survey_id):
        questions = self.cursor.execute(
            "SELECT id FROM questions WHERE survey_id = ? ORDER BY position, id",
            (survey_id,)).fetchall()
        
        for index, question in enumerate(questions, start=1):
            self.cursor.execute(
                "UPDATE questions SET position = ? WHERE id = ?",
                (index, question["id"]))
        self.connection.commit()
        self.reorder_positions(survey_id)
        return True

    def move_question(self, question_id, new_position):
        question = self.get_question(question_id)
        if not question:
            return False

        self.cursor.execute(
            "UPDATE questions SET position = ? WHERE id = ?",
            (new_position - 0.5, question_id))  # valor flotante temporal para evitar colisiones
        self.connection.commit()
        self.reorder_positions(question["survey_id"])
        return True
    
    def get_question(self, question_id):
        return self.cursor.execute("SELECT * FROM questions WHERE id = ?", (question_id,)).fetchone()

    def list_questions(self, survey_id):
        return self.cursor.execute(
            "SELECT * FROM questions WHERE survey_id = ? ORDER BY position",
            (survey_id,)).fetchall()

class QuestionOptions:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_option(self, question_id, option_text):
        try:
            self.cursor.execute(
                "INSERT INTO question_options (question_id, option_text) VALUES (?, ?)",
                (question_id, option_text))
            self.connection.commit()
            self.reorder_positions(question_id)
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False

    def reorder_positions(self, question_id):
        options = self.cursor.execute(
            "SELECT id FROM question_options WHERE question_id = ? ORDER BY position, id",
            (question_id,)).fetchall()

        for index, option in enumerate(options, start=1):
            self.cursor.execute(
                "UPDATE question_options SET position = ? WHERE id = ?",
                (index, option["id"]))
        self.connection.commit()

    def move_option(self, option_id, new_position):
        option = self.get_option(option_id)
        if not option:
            return False

        self.cursor.execute(
            "UPDATE question_options SET position = ? WHERE id = ?",
            (new_position - 0.5, option_id))
        self.connection.commit()
        self.reorder_positions(option["question_id"])
        return True

    def get_option(self, option_id):
        return self.cursor.execute("SELECT * FROM question_options WHERE id = ?",(option_id,)).fetchone()

    def list_options(self, question_id):
        return self.cursor.execute("SELECT * FROM question_options WHERE question_id = ? ORDER BY position",(question_id,)).fetchall()

    def remove_option(self, option_id):
        option = self.get_option(option_id)
        if not option:
            return False
        question_id = option["question_id"]
        self.cursor.execute("DELETE FROM question_options WHERE id = ?", (option_id,))
        self.connection.commit()
        self.reorder_positions(question_id)
        return True

class SubmittedAnswers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

class Answers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

class Statistics:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()