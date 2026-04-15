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
                id INTEGER              PRIMARY KEY AUTOINCREMENT,
                creator_id              INTEGER NOT NULL,
                title                   VARCHAR(200) NOT NULL,
                description             TEXT,
                is_public               CHAR(1) DEFAULT 'y' CHECK(is_public IN ('y','n')),
                start_at                TEXT,
                end_at                  TEXT,
                created_at              TEXT NOT NULL,
                last_modified           TEXT NOT NULL,
                FOREIGN KEY (creator_id) REFERENCES user(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS survey_admin (
                survey_id               INTEGER NOT NULL,
                user_id                 INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS survey_whitelist (
                survey_id               INTEGER NOT NULL,
                user_id                 INTEGER NOT NULL,
                PRIMARY KEY (survey_id, user_id),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)   REFERENCES user(id)   ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS question (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_id               INTEGER NOT NULL,
                is_demographic          BOOL,
                title                   TEXT NOT NULL,
                type                    CHAR(1) DEFAULT 't' CHECK(type IN ('t', 'n', 's', 'm')),
                position                INT DEFAULT 0,
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS question_option (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id             INTEGER NOT NULL,
                option_text             TEXT NOT NULL,
                position                INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (question_id) REFERENCES question(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS submitted_answer (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_id               INTEGER NOT NULL,
                user_hash               TEXT NOT NULL,
                submitted_at            TEXT NOT NULL,
                demographic_group       TEXT,
                UNIQUE (survey_id, user_hash),
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE);
                                  
            CREATE TABLE IF NOT EXISTS answer (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_answer_id    INTEGER NOT NULL,
                question_id             INTEGER NOT NULL,
                option_id               INTEGER,
                answer                  TEXT,
                UNIQUE (submitted_answer_id, question_id),
                FOREIGN KEY (submitted_answer_id) REFERENCES submitted_answer(id) ON DELETE CASCADE,
                FOREIGN KEY (question_id) REFERENCES question(id) ON DELETE CASCADE,
                FOREIGN KEY (option_id) REFERENCES question_option(id) ON DELETE CASCADE);
            
            CREATE TABLE IF NOT EXISTS statistic (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_id               INTEGER NOT NULL,
                demographic_group       TEXT,
                count                   INTEGER,
                stat_type               TEXT DEFAULT 'sum' CHECK(stat_type IN ('sum','average')),
                value                   TEXT,
                FOREIGN KEY (survey_id) REFERENCES survey(id) ON DELETE CASCADE);
        ''')
        self.connection.commit()
    
    def add_survey(self, creator_id, title, description, start_at, end_at, is_public='y'):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO survey (creator_id, title, description, is_public, start_at, end_at, created_at, last_modified) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (creator_id, title, description, is_public, start_at, end_at, now, now))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False
        
    def get_survey(self, survey_id):
        return self.cursor.execute("SELECT * FROM survey WHERE id = ?", (survey_id,)).fetchone()

    def modify_dates(self, survey_id, start, end):
        self.cursor.execute("UPDATE survey SET start_at=?, end_at=?, last_modified=? WHERE id = ?",
            (start, end, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), survey_id))
        self.connection.commit()


    # PARA ADMIN
    def list_surveys(self):
        return self.cursor.execute("SELECT * FROM survey").fetchall()
    
    def list_surveys_creator(self, user):
        return self.cursor.execute("SELECT * FROM survey WHERE creator_id = ?", (user,)).fetchall()
    
    def list_surveys_admin(self, user_id):
        return self.cursor.execute("""
            SELECT survey.* FROM survey
            JOIN survey_admin ON survey.id = survey_admin.survey_id
            WHERE survey_admin.user_id = ?""", (user_id,)).fetchall()
    
    def get_user_surveys(self, username):
        """Obtiene todas las encuestas creadas por un usuario."""
        return self.cursor.execute("SELECT * FROM survey WHERE creator_id = ?", (username,)).fetchall()
    
    def get_public_surveys(self, username):
        """Obtiene todas las encuestas públicas creadas por un usuario específico."""
        return self.cursor.execute(
            "SELECT * FROM survey WHERE creator_id = ? AND is_public = 'y'", 
            (username,)).fetchall()
    
    def has_voted(self, survey_id, user_hash):
        """Verifica si un usuario ya ha votado en una encuesta."""
        result = self.cursor.execute(
            "SELECT 1 FROM submitted_answer WHERE survey_id = ? AND user_hash = ?",
            (survey_id, user_hash)).fetchone()
        return result is not None
    
    def delete_survey(self, survey_id):
        self.cursor.execute("DELETE FROM survey WHERE id = ?", (survey_id,))
        self.connection.commit()
        


class SurveyAdmins:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_admin(self, survey_id, user_id):
        try:
            self.cursor.execute(
                "INSERT INTO survey_admin (survey_id, user_id) VALUES (?, ?)",
                (survey_id, user_id))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_admin(self, survey_id, user_id):
        self.cursor.execute(
            "DELETE FROM survey_admin WHERE survey_id = ? AND user_id = ?",
            (survey_id, user_id))
        self.connection.commit()

    def list_admins(self, survey_id):
        return self.cursor.execute(
            "SELECT user_id FROM survey_admin WHERE survey_id = ?",
            (survey_id,)).fetchall()

    def is_admin(self, survey_id, user_id):
        result = self.cursor.execute(
            "SELECT 1 FROM survey_admin WHERE survey_id = ? AND user_id = ?",
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
    
    def add_question(self, survey_id, is_demographic, title, type):
        try:
            self.cursor.execute(
                "INSERT INTO question (survey_id, is_demographic, title, type) VALUES (?, ?, ?, ?)",
                (survey_id, is_demographic, title, type))
            self.connection.commit()
            self.reorder_positions(survey_id)
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False
        
    def remove_question(self, question_id):
        question = self.get_question(question_id)
        if not question:
            return False
        survey_id = question["survey_id"]
        self.cursor.execute("DELETE FROM question WHERE id = ?", (question_id,))
        self.connection.commit()
        self.reorder_positions(survey_id)
        return True
    
    def reorder_positions(self, survey_id):
        questions = self.cursor.execute(
            "SELECT id FROM question WHERE survey_id = ? ORDER BY position, id",
            (survey_id,)).fetchall()
        
        for index, question in enumerate(questions, start=1):
            self.cursor.execute(
                "UPDATE question SET position = ? WHERE id = ?",
                (index, question["id"]))
        self.connection.commit()
        return True

    def move_question(self, question_id, new_position):
        question = self.get_question(question_id)
        if not question:
            return False

        self.cursor.execute(
            "UPDATE question SET position = ? WHERE id = ?",
            (new_position - 0.5, question_id))  # valor flotante temporal para evitar colisiones
        self.connection.commit()
        self.reorder_positions(question["survey_id"])
        return True
    
    def get_question(self, question_id):
        return self.cursor.execute("SELECT * FROM question WHERE id = ?", (question_id,)).fetchone()

    def list_questions(self, survey_id, demographic=None):
        if demographic is not None:
            return self.cursor.execute("SELECT * FROM question WHERE survey_id = ? AND is_demographic = ? ORDER BY position",
                (survey_id, demographic)).fetchall()
        else:
            return self.cursor.execute("SELECT * FROM question WHERE survey_id = ? ORDER BY position",(survey_id,)).fetchall()
    
    def update_question(self, question_id, title, type, is_demographic=None):
        if is_demographic is not None:
            self.cursor.execute("UPDATE question SET title = ?, type = ?, is_demographic = ? WHERE id = ?",
                (title, type, is_demographic, question_id))
        else:
            self.cursor.execute("UPDATE question SET title = ?, type = ? WHERE id = ?",
                (title, type, question_id))
        self.connection.commit()
        return True
    
    def update_question_position(self, question_id, position):
        """Actualiza la posición de una pregunta."""
        self.cursor.execute("UPDATE question SET position = ? WHERE id = ?",
            (position, question_id))
        self.connection.commit()
        return True
    


class QuestionOptions:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_option(self, question_id, option_text):
        try:
            self.cursor.execute(
                "INSERT INTO question_option (question_id, option_text) VALUES (?, ?)",
                (question_id, option_text))
            self.connection.commit()
            self.reorder_positions(question_id)
            return True
        except sqlite3.IntegrityError:
            return False

    def reorder_positions(self, question_id):
        options = self.cursor.execute(
            "SELECT id FROM question_option WHERE question_id = ? ORDER BY position, id",
            (question_id,)).fetchall()

        for index, option in enumerate(options, start=1):
            self.cursor.execute(
                "UPDATE question_option SET position = ? WHERE id = ?",
                (index, option["id"]))
        self.connection.commit()

    def move_option(self, option_id, new_position):
        option = self.get_option(option_id)
        if not option:
            return False

        self.cursor.execute(
            "UPDATE question_option SET position = ? WHERE id = ?",
            (new_position - 0.5, option_id))
        self.connection.commit()
        self.reorder_positions(option["question_id"])
        return True

    def get_option(self, option_id):
        return self.cursor.execute("SELECT * FROM question_option WHERE id = ?",(option_id,)).fetchone()

    def list_options(self, question_id):
        return self.cursor.execute("SELECT * FROM question_option WHERE question_id = ? ORDER BY position",(question_id,)).fetchall()

    def update_option(self, option_id, option_text):
        """Actualiza el texto de una opción."""
        self.cursor.execute("UPDATE question_option SET option_text = ? WHERE id = ?",
            (option_text, option_id))
        self.connection.commit()
        return True

    def remove_option(self, option_id):
        option = self.get_option(option_id)
        if not option:
            return False
        question_id = option["question_id"]
        self.cursor.execute("DELETE FROM question_option WHERE id = ?", (option_id,))
        self.connection.commit()
        self.reorder_positions(question_id)
        return True

class SubmittedAnswers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_submitted_answer(self, survey_id, user_hash, demographic_group):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO submitted_answer (survey_id, user_hash, submitted_at, demographic_group) VALUES (?, ?, ?, ?)",
                (survey_id, user_hash, now, demographic_group))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False
    
    def remove_submitted_answer(self, answer_id):
        try:
            self.cursor.execute(
                "DELETE FROM submitted_answer WHERE id = ?", (answer_id,))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_user_submitted_answer(self, user_hash):
        return self.cursor.execute("SELECT * FROM submitted_answer WHERE user_hash = ?",(user_hash,)).fetchone()
    
    def get_usurvey_submitted_answers(self, survey):
        return self.cursor.execute("SELECT * FROM submitted_answer WHERE survey_id = ?",(survey,)).fetchall()
    

class Answers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def add_answer(self, submitted_answer_id, question_id, option_id, answer):
        try:
            self.cursor.execute(
                "INSERT INTO answer (submitted_answer_id, question_id, option_id, answer) VALUES (?, ?, ?, ?)",
                (submitted_answer_id, question_id, option_id, answer))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def remove_answer(self, answer_id):
        try:
            self.cursor.execute("DELETE FROM answer WHERE id = ?", (answer_id,))
            self.connection.commit()
        except sqlite3.IntegrityError:
            return False
    
    def get_value(self, answer_id):
        answer = self.cursor.execute("SELECT * FROM answer WHERE id = ?", (answer_id,)).fetchone()
        if not answer:
            return False
        if answer["option_id"] is not None:
            return (answer["option_id"], "option_id")
        elif answer["answer"] is not None:
            return (answer["answer"], "answer")
        return False


class Statistics:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def add_value(self, survey_id, demographic_group, stat_type):
        try:
            self.cursor.execute(
                "INSERT INTO statistic (survey_id, demographic_group, count, stat_type, value) VALUES (?, ?, ?, ?, ?)",
                (survey_id, demographic_group, 0, stat_type, 0))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_value_demo(self, survey_id, demographic_group):
        return self.cursor.execute("SELECT * FROM statistic WHERE survey_id = ? AND demographic_group = ?",
            (survey_id, demographic_group)).fetchone()
    
    def get_values(self, survey_id):
        return self.cursor.execute("SELECT * FROM statistic WHERE survey_id = ?", (survey_id,)).fetchall()
    
    def update_values(self, survey_id, demographic_group, count, stat_type, value):
        try:
            self.cursor.execute(
                "UPDATE statistic SET count = ?, value = ? WHERE survey_id = ? AND demographic_group = ? AND stat_type = ?",
                (count, value, survey_id, demographic_group, stat_type))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def add_all_values(self, survey_id, demographic_group):
        stat_types = ["sum", "average"]
        for type in stat_types:
            self.add_value(survey_id, demographic_group, type)