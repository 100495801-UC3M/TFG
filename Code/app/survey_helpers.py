"""
app/survey_helpers.py — Funciones auxiliares para gestión de encuestas
"""


def load_questions_with_options(survey_id, questions_db, question_options_db):
    """Carga las preguntas de una encuesta e incluye sus opciones."""
    questions = questions_db.list_questions(survey_id)
    questions_list = []
    for question in questions:
        question_dict = dict(question)
        if question_dict["type"] in ["s", "m"]:
            question_dict["options"] = question_options_db.list_options(question_dict["id"])
        else:
            question_dict["options"] = []
        questions_list.append(question_dict)
    return questions_list


def parse_visibility(form_value):
    """Convierte el valor del select de visibilidad en (is_public, privacy_mode, access_code)."""
    import secrets
    
    if form_value == 'y':
        return 'y', 'public', None
    elif form_value == 'whitelist':
        return 'n', 'whitelist', None
    elif form_value == 'code':
        return 'n', 'code', secrets.token_urlsafe(8)
    # fallback
    return 'n', 'public', None


def check_survey_access(survey, username, survey_admins_db, survey_whitelist_db):
    """
    Comprueba si `username` puede acceder (votar) a la encuesta.
    Retorna (allowed: bool, reason: str).
    """
    mode = survey["privacy_mode"] or "public"
    if mode == "public":
        return True, ""
    creator = survey["creator_id"]
    if username == creator:
        return True, ""
    if survey_admins_db.is_admin(survey["id"], username):
        return True, ""
    if mode == "whitelist":
        if survey_whitelist_db.is_allowed(survey["id"], username):
            return True, ""
        return False, "No estás en la lista blanca de esta encuesta."
    if mode == "code":
        # El acceso por código se gestiona en la ruta vote_survey
        return True, ""
    return False, "No tienes acceso a esta encuesta."


def build_numeric_stats_list(survey_id, questions_db, survey_db, submitted_answers_db):
    """
    Construye lista de estadísticas numéricas: [0, 478, 0, 2, ...]
    con ceros para preguntas no-numéricas.
    
    Retorna: lista de floats con respuestas numéricas agrupadas por pregunta.
    """
    questions = questions_db.list_questions(survey_id)
    stats_list = []
    
    for question in questions:
        if question["type"] != 'n':
            # Preguntas no-numéricas → 0
            stats_list.append(0.0)
        else:
            # Preguntas numéricas → sumar todas las respuestas
            rows = survey_db.connection.execute("""
                SELECT a.answer FROM answer a
                JOIN submitted_answer sa ON a.submitted_answer_id = sa.id
                WHERE sa.survey_id = ? AND a.question_id = ? AND a.answer IS NOT NULL
            """, (survey_id, question["id"])).fetchall()
            
            total = 0.0
            for row in rows:
                try:
                    total += float(row[0])
                except (ValueError, TypeError):
                    pass
            stats_list.append(total)
    
    return stats_list
