import sqlite3
from datetime import datetime

class Survey:
    def __init__(self, db_name="./db/survey.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_tables()
        self._migrate()

    def create_tables(self):
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS survey (
                id INTEGER              PRIMARY KEY AUTOINCREMENT,
                creator_id              INTEGER NOT NULL,
                title                   VARCHAR(200) NOT NULL,
                description             TEXT,
                privacy_mode            TEXT DEFAULT 'public',
                access_code             TEXT,
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
                is_required             BOOL DEFAULT 1,
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
                submitted_answer_id     INTEGER NOT NULL,
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

    def _migrate(self):
        migrations = [
            "ALTER TABLE survey ADD COLUMN privacy_mode TEXT DEFAULT 'public'",
            "ALTER TABLE survey ADD COLUMN access_code TEXT",
            "ALTER TABLE survey ADD COLUMN survey_key TEXT",
        ]
        for sql in migrations:
            try:
                self.cursor.execute(sql)
                self.connection.commit()
            except Exception:
                pass

    def add_survey(self, creator_id, title, description, start_at, end_at,
                privacy_mode='public', access_code=None, survey_key=None):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO survey (creator_id, title, description, privacy_mode, "
                "access_code, start_at, end_at, created_at, last_modified, survey_key) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (creator_id, title, description, privacy_mode,
                access_code, start_at, end_at, now, now, survey_key))
            self.connection.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            return False
        
    # Obtiene el campo survey_key cifrado de una encuesta.
    def get_survey_key(self, survey_id):
        row = self.cursor.execute(
            "SELECT survey_key FROM survey WHERE id = ?", (survey_id,)).fetchone()
        return row["survey_key"] if row else None
        
    def get_survey(self, survey_id):
        return self.cursor.execute("SELECT * FROM survey WHERE id = ?", (survey_id,)).fetchone()

    def get_survey_by_code(self, access_code):
        """Busca una encuesta por su código de acceso."""
        return self.cursor.execute(
            "SELECT * FROM survey WHERE access_code = ?", (access_code,)).fetchone()

    def modify_survey(self, survey_id, start, end,
                      privacy_mode=None, access_code=None):
        if privacy_mode is not None:
            self.cursor.execute(
                "UPDATE survey SET start_at=?, end_at=?, privacy_mode=?, "
                "access_code=?, last_modified=? WHERE id=?",
                (start, end, privacy_mode, access_code,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"), survey_id))
        else:
            self.cursor.execute(
                "UPDATE survey SET start_at=?, end_at=?, last_modified=? WHERE id=?",
                (start, end,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"), survey_id))
        self.connection.commit()

    def is_ended(self, survey):
        """Devuelve True si la encuesta ha finalizado."""
        if not survey["end_at"]:
            return False
        try:
            end = datetime.fromisoformat(survey["end_at"])
            return datetime.now() > end
        except Exception:
            return False

    def is_started(self, survey):
        """Devuelve True si la encuesta ha comenzado."""
        if not survey["start_at"]:
            return True  # Si no tiene start_at, se considera que ya comenzó
        try:
            start = datetime.fromisoformat(survey["start_at"])
            return datetime.now() >= start
        except Exception:
            return True

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
    
    def get_user_surveys(self, username, limit=None, offset=0):
        """Obtiene encuestas del usuario con paginación opcional."""
        if limit:
            return self.cursor.execute(
                "SELECT * FROM survey WHERE creator_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", 
                (username, limit, offset)).fetchall()
        return self.cursor.execute(
            "SELECT * FROM survey WHERE creator_id = ? ORDER BY created_at DESC", 
            (username,)).fetchall()
    
    def count_user_surveys(self, username):
        """Cuenta total de encuestas del usuario."""
        result = self.cursor.execute(
            "SELECT COUNT(*) as count FROM survey WHERE creator_id = ?", 
            (username,)).fetchone()
        return result["count"]
    
    def get_public_surveys(self, username, limit=None, offset=0):
        """Obtiene encuestas públicas de un usuario con paginación opcional."""
        if limit:
            return self.cursor.execute(
                "SELECT * FROM survey WHERE creator_id = ? AND privacy_mode = 'public' ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (username, limit, offset)).fetchall()
        return self.cursor.execute(
            "SELECT * FROM survey WHERE creator_id = ? AND privacy_mode = 'public' ORDER BY created_at DESC",
            (username,)).fetchall()
    
    def count_public_surveys(self, username):
        """Cuenta total de encuestas públicas de un usuario."""
        result = self.cursor.execute(
            "SELECT COUNT(*) as count FROM survey WHERE creator_id = ? AND privacy_mode = 'public'", 
            (username,)).fetchone()
        return result["count"]

    def get_surveys_as_admin(self, username, limit=None, offset=0):
        """Encuestas en las que el usuario es admin (pero no el creador)."""
        if limit:
            return self.cursor.execute("""
                SELECT survey.* FROM survey
                JOIN survey_admin ON survey.id = survey_admin.survey_id
                WHERE survey_admin.user_id = ? AND survey.creator_id != ?
                ORDER BY survey.created_at DESC
                LIMIT ? OFFSET ?
            """, (username, username, limit, offset)).fetchall()
        return self.cursor.execute("""
            SELECT survey.* FROM survey
            JOIN survey_admin ON survey.id = survey_admin.survey_id
            WHERE survey_admin.user_id = ? AND survey.creator_id != ?
            ORDER BY survey.created_at DESC
        """, (username, username)).fetchall()
    
    def count_surveys_as_admin(self, username):
        """Cuenta total de encuestas donde el usuario es admin."""
        result = self.cursor.execute("""
            SELECT COUNT(DISTINCT survey.id) as count FROM survey
            JOIN survey_admin ON survey.id = survey_admin.survey_id
            WHERE survey_admin.user_id = ? AND survey.creator_id != ?
        """, (username, username)).fetchone()
        return result["count"]

    def has_voted(self, survey_id, user_hash):
        result = self.cursor.execute(
            "SELECT 1 FROM submitted_answer WHERE survey_id = ? AND user_hash = ?",
            (survey_id, user_hash)).fetchone()
        return result is not None
    
    def delete_survey(self, survey_id):
        self.cursor.execute("DELETE FROM survey WHERE id = ?", (survey_id,))
        self.connection.commit()
    
    def get_surveys_as_whitelist(self, username, limit=None, offset=0):
        if limit:
            return self.cursor.execute("""
                SELECT survey.* FROM survey
                JOIN survey_whitelist ON survey.id = survey_whitelist.survey_id
                WHERE survey_whitelist.user_id = ? AND survey.creator_id != ?
                ORDER BY survey.created_at DESC
                LIMIT ? OFFSET ?
            """, (username, username, limit, offset)).fetchall()
        return self.cursor.execute("""
            SELECT survey.* FROM survey
            JOIN survey_whitelist ON survey.id = survey_whitelist.survey_id
            WHERE survey_whitelist.user_id = ? AND survey.creator_id != ?
            ORDER BY survey.created_at DESC
        """, (username, username)).fetchall()

    def count_surveys_as_whitelist(self, username):
        result = self.cursor.execute("""
            SELECT COUNT(DISTINCT survey.id) as count FROM survey
            JOIN survey_whitelist ON survey.id = survey_whitelist.survey_id
            WHERE survey_whitelist.user_id = ? AND survey.creator_id != ?
        """, (username, username)).fetchone()
        return result["count"]

    # Estadísticas Python (sin SEAL)

    def get_vote_count(self, survey_id):
        """Total de respuestas enviadas a la encuesta."""
        row = self.cursor.execute(
            "SELECT COUNT(*) FROM submitted_answer WHERE survey_id = ?",
            (survey_id,)).fetchone()
        return row[0] if row else 0

    def get_option_counts(self, survey_id):
        """Para preguntas de opción: {option_id: count}."""
        rows = self.cursor.execute("""
            SELECT a.option_id, COUNT(*) as cnt
            FROM answer a
            JOIN submitted_answer sa ON a.submitted_answer_id = sa.id
            WHERE sa.survey_id = ? AND a.option_id IS NOT NULL
            GROUP BY a.option_id
        """, (survey_id,)).fetchall()
        return {row["option_id"]: row["cnt"] for row in rows}

    def get_numeric_stats(self, survey_id, question_id):
        """Para preguntas numéricas: {sum, average, count}."""
        rows = self.cursor.execute("""
            SELECT a.answer
            FROM answer a
            JOIN submitted_answer sa ON a.submitted_answer_id = sa.id
            WHERE sa.survey_id = ? AND a.question_id = ? AND a.answer IS NOT NULL
        """, (survey_id, question_id)).fetchall()
        values = []
        for r in rows:
            try:
                values.append(float(r["answer"]))
            except Exception:
                pass
        if not values:
            return {"sum": 0, "average": 0, "count": 0}
        return {
            "sum": sum(values),
            "average": sum(values) / len(values),
            "count": len(values)
        }

    def get_text_answers(self, survey_id, question_id):
        """Para preguntas de texto: lista de respuestas."""
        rows = self.cursor.execute("""
            SELECT a.answer
            FROM answer a
            JOIN submitted_answer sa ON a.submitted_answer_id = sa.id
            WHERE sa.survey_id = ? AND a.question_id = ? AND a.answer IS NOT NULL
        """, (survey_id, question_id)).fetchall()
        return [r["answer"] for r in rows]

    # Función para cambiar la base de datos ejecutando en este .py
    def changes_to_database(self, command):
        self.cursor.execute(command)
        self.connection.commit()
        print("OK")

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
    
    def add_question(self, survey_id, is_demographic, title, type, is_required=True):
        try:
            max_pos = self.cursor.execute(
                "SELECT COALESCE(MAX(position), 0) FROM question WHERE survey_id = ?",
                (survey_id,)).fetchone()[0]
            self.cursor.execute(
                "INSERT INTO question (survey_id, is_demographic, title, type, is_required, position) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (survey_id, is_demographic, title, type, is_required, max_pos + 1))
            self.connection.commit()
            return self.cursor.lastrowid
        except Exception:
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
            (new_position - 0.5, question_id))
        self.connection.commit()
        self.reorder_positions(question["survey_id"])
        return True
    
    def get_question(self, question_id):
        return self.cursor.execute(
            "SELECT * FROM question WHERE id = ?", (question_id,)).fetchone()

    def list_questions(self, survey_id, demographic=None):
        if demographic is not None:
            return self.cursor.execute(
                "SELECT * FROM question WHERE survey_id = ? AND is_demographic = ? ORDER BY position",
                (survey_id, demographic)).fetchall()
        return self.cursor.execute(
            "SELECT * FROM question WHERE survey_id = ? ORDER BY position",
            (survey_id,)).fetchall()
    
    def update_question(self, question_id, title, type, is_demographic, is_required):
        self.cursor.execute(
            "UPDATE question SET title=?, type=?, is_demographic=?, is_required=? WHERE id=?",
            (title, type, int(is_demographic), int(is_required), question_id))
        self.connection.commit()
        return True
        
    def update_question_position(self, question_id, position):
        self.cursor.execute(
            "UPDATE question SET position = ? WHERE id = ?", (position, question_id))
        self.connection.commit()
        return True


class QuestionOptions:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_option(self, question_id, option_text):
        try:
            max_pos = self.cursor.execute(
                "SELECT COALESCE(MAX(position), 0) FROM question_option WHERE question_id = ?",
                (question_id,)).fetchone()[0]
            self.cursor.execute(
                "INSERT INTO question_option (question_id, option_text, position) VALUES (?, ?, ?)",
                (question_id, option_text, max_pos + 1))
            self.connection.commit()
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
        return self.cursor.execute(
            "SELECT * FROM question_option WHERE id = ?", (option_id,)).fetchone()

    def list_options(self, question_id):
        return self.cursor.execute(
            "SELECT * FROM question_option WHERE question_id = ? ORDER BY position",
            (question_id,)).fetchall()

    def update_option(self, option_id, option_text):
        self.cursor.execute(
            "UPDATE question_option SET option_text = ? WHERE id = ?",
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
    
    def remove_all_options(self, question_id):
        """Elimina todas las opciones de una pregunta."""
        self.cursor.execute("DELETE FROM question_option WHERE question_id = ?", (question_id,))
        self.connection.commit()


class SubmittedAnswers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()

    def add_submitted_answer(self, survey_id, user_hash, demographic_group):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO submitted_answer (survey_id, user_hash, submitted_at, demographic_group) "
                "VALUES (?, ?, ?, ?)",
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
    
    def get_user_submitted_answer(self, user_hash, survey_id):
        return self.cursor.execute(
            "SELECT * FROM submitted_answer WHERE user_hash = ? AND survey_id = ?",
            (user_hash, survey_id)).fetchone()
    
    def get_survey_submitted_answers(self, survey):
        return self.cursor.execute(
            "SELECT * FROM submitted_answer WHERE survey_id = ?",
            (survey,)).fetchall()


class Answers:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def add_answer(self, submitted_answer_id, question_id, option_id, answer):
        try:
            self.cursor.execute(
                "INSERT INTO answer (submitted_answer_id, question_id, option_id, answer) "
                "VALUES (?, ?, ?, ?)",
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
        answer = self.cursor.execute(
            "SELECT * FROM answer WHERE id = ?", (answer_id,)).fetchone()
        if not answer:
            return False
        if answer["option_id"] is not None:
            return (answer["option_id"], "option_id")
        elif answer["answer"] is not None:
            return (answer["answer"], "answer")
        return False

    def get_answers(self, submitted_answer_id):
        return self.cursor.execute(
            "SELECT * FROM answer WHERE submitted_answer_id = ?",
            (submitted_answer_id,)).fetchall()


class Statistics:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def add_value(self, survey_id, demographic_group, stat_type):
        try:
            self.cursor.execute(
                "INSERT INTO statistic (survey_id, demographic_group, count, stat_type, value) "
                "VALUES (?, ?, ?, ?, ?)",
                (survey_id, demographic_group, 0, stat_type, 0))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_value_demo(self, survey_id, demographic_group):
        return self.cursor.execute(
            "SELECT * FROM statistic WHERE survey_id = ? AND demographic_group = ?",
            (survey_id, demographic_group)).fetchone()
    
    def get_values(self, survey_id):
        return self.cursor.execute(
            "SELECT * FROM statistic WHERE survey_id = ?", (survey_id,)).fetchall()
    
    def update_values(self, survey_id, demographic_group, count, stat_type, value):
        try:
            self.cursor.execute(
                "UPDATE statistic SET count = ?, value = ? "
                "WHERE survey_id = ? AND demographic_group = ? AND stat_type = ?",
                (count, value, survey_id, demographic_group, stat_type))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def add_all_values(self, survey_id, demographic_group):
        for t in ["sum", "average"]:
            self.add_value(survey_id, demographic_group, t)

if __name__ == "__main__":
    survey_db = Survey()
    survey_db.changes_to_database("")