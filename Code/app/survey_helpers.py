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
            # Preguntas no-numéricas -> 0
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


def send_surveys_to_server(survey_id, demographic_group, answers_plain, statistics_db, cliente_seal):
    """
    Envía respuestas numéricas al servidor SEAL para calcular estadísticas
    cifradas mediante operaciones homomorfas.

    Parámetros:
      - survey_id         : id de la encuesta
      - demographic_group : grupo demográfico (ej: pregunta_id como string)
      - answers_plain     : lista[float] de respuestas sin cifrar
      - statistics_db     : instancia de base de datos de estadísticas
      - cliente_seal      : cliente de conexión al servidor SEAL

    Retorna True si el servidor procesó exitosamente, False en caso contrario.
    """
    import logging
    
    try:
        if not answers_plain:
            return False

        # Recuperar lista encriptada anterior de BD (será None si es la primera vez)
        existing = statistics_db.get_value_demo(survey_id, demographic_group)
        lista1_encrypted_base64 = None
        if existing and existing['stat_type'] == 'sum':
            lista1_encrypted_base64 = existing['value']

        # Llamada al servidor C++ vía cppclient
        # Ambos métodos reciben: lista2_plain, lista1_encrypted_base64
        # cppclient solo encripta lista2, deserializa lista1 si existe
        result_sum_b64 = cliente_seal.compute_sum(answers_plain, lista1_encrypted_base64)
        result_avg_b64 = cliente_seal.compute_average(answers_plain, lista1_encrypted_base64)

        if result_sum_b64 is None or result_avg_b64 is None:
            logging.warning(f"SEAL retornó None para survey {survey_id}, grupo {demographic_group}")
            return False

        n = len(answers_plain)

        # Insertar o actualizar en la tabla statistics
        if existing:
            statistics_db.update_values(survey_id, demographic_group, n, 'sum', result_sum_b64)
            statistics_db.update_values(survey_id, demographic_group, n, 'average', result_avg_b64)
        else:
            statistics_db.add_all_values(survey_id, demographic_group)
            statistics_db.update_values(survey_id, demographic_group, n, 'sum', result_sum_b64)
            statistics_db.update_values(survey_id, demographic_group, n, 'average', result_avg_b64)

        logging.info(f"Estadísticas SEAL actualizadas – encuesta {survey_id}, grupo {demographic_group}")
        return True

    except Exception as e:
        logging.error(f"Error actualizando estadísticas SEAL: {e}")
        return False


def trigger_seal_for_survey(survey_id, questions_db, survey_db, submittedAnswers_db, statistics_db, cliente_seal):
    """
    Itera las preguntas numéricas de la encuesta y calcula estadísticas cifradas.
    Se invoca tras cada nueva votación.
    Devuelve True si todo fue bien, False si alguna llamada falló.
    """
    import logging
    
    try:
        # Construir lista de estadísticas numéricas: [0, suma, 0, media, ...]
        # Solo procesa preguntas numéricas, pone 0 en las demás
        stats_list = build_numeric_stats_list(survey_id, questions_db, survey_db, submittedAnswers_db)
        
        if not stats_list or sum(stats_list) == 0:
            logging.debug(f"Sin datos numéricos para encuesta {survey_id}")
            return True

        # Agrupar por survey (demographic_group = "numeric_stats")
        demographic_group = "numeric_stats"
        
        return send_surveys_to_server(survey_id, demographic_group, stats_list, statistics_db, cliente_seal)

    except Exception as e:
        logging.error(f"Error en trigger_seal_for_survey: {e}")
        return False
