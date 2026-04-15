import os
import re
import base64
import logging
import json
import requests
import time
import uuid
import secrets
from datetime import timedelta
import app.security as security
from app.users import Users
import app.cppclient as client
from app.survey import Survey, SurveyAdmins, SurveyWhitelist, Questions, QuestionOptions, Answers, SubmittedAnswers, Statistics
# TODO Quitar para mensajes
from app.messages import Messages
from flask import Flask, render_template, request, redirect, url_for, session, abort


# Iniciamos el servidor flask
app = Flask(__name__)

# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

# Límite de sesión de 5 minutos
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# Inicializamos las bases de datos y sus tablas
users_db            = Users()
#messages_db        = Messages()
survey_db           = Survey()
surveyAdmins_db     = SurveyAdmins(survey_db.connection)
surveyWhitelist_db  = SurveyWhitelist(survey_db.connection)
questions_db        = Questions(survey_db.connection)
questionOptions_dn  = QuestionOptions(survey_db.connection)
answers_db          = Answers(survey_db.connection)
submittedAnswers_db = SubmittedAnswers(survey_db.connection)
statistics_db       = Statistics(survey_db.connection)


# Inicializamos las variables globales
pending_registrations = {}
reset_tokens = {}

# Clave secreta para realizar búsquedas de elementos cifrados
SECRET_KEY = security.load_search_secret()


# Configuración logging para que se muestre en la consola
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


route = "/"
@app.route(route)
def index():
    # Ruta de la página de inicio de la web
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        DNI         = request.form["DNI"].strip().upper()
        name        = request.form["username"].strip().lower()
        email       = request.form["email"].strip().lower()
        password    = request.form["password"]
        password2   = request.form["password2"]

        error = security.DNI_valid(DNI)
        if error[0] == False:
            return render_template("register.html", error=error[1])
        
        if "@" in name:
            return render_template("register.html", error="El usuario no puede tener @")

        if not security.check_password(password):
            error = ("La contraseña es inválida. Debe tener al menos 6 "
                     "caracteres, una mayúscula, una minúscula, un número y "
                     "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                     "espacios.")
            return render_template("register.html", error=error)

        if password != password2:
            return render_template("register.html", error="Las contraseñas no coinciden")

        dni_index = security.make_search_index(DNI, SECRET_KEY)
        email_index = security.make_search_index(email, SECRET_KEY)
        if users_db.check_user(dni_index, "DNI") or users_db.check_user(email_index, "email") or users_db.check_user(name, "name"):
            return render_template("register.html", error="Usuario, email o DNI ya registrado.")

        salt                    = security.generate_salt_aes("salt", 16)
        dni_encrypted           = security.encrypt_field(DNI, SECRET_KEY)
        email_encrypted         = security.encrypt_field(email, SECRET_KEY)
        hashed_password         = security.hash(password, salt)
        private_key, public_key = security.generate_keys()
        private_key_encrypted   = security.encrypt_private_key(private_key, password, salt)
        security.create_request(name, public_key, private_key)

        # Generar token único con expiración de 5 minutos
        token = str(uuid.uuid4())
        pending_registrations[token] = {
            "DNI":              dni_index,
            "DNI_search":       dni_encrypted,
            "name":             name,
            "email":            email_index,
            "email_search":     email_encrypted,
            "hashed_password":  hashed_password,
            "salt":             base64.urlsafe_b64encode(salt).decode(),
            "private_key":      private_key_encrypted,
            "expires_at":       time.time() + 300,  # 5 minutos
        }

        confirm_url = f"https://localhost:5000/confirm/{token}"

        subject = "Intento de registro en AGULE"
        body = (
            f"Se le envía este correo para confirmar su registro en la aplicación AGULE.\n\n"
            f"Dispone de 5 minutos para completar el registro.\n\n"
            f"Para ello, haga clic en el siguiente enlace:\n{confirm_url}\n\n"
            f"Si no ha solicitado este registro, ignore este correo."
        )

        status, response = security.send_email_gmail_api('"AGULE - Registro" <mariohidtfg@gmail.com>', email,
            subject, body)

        if status == 200:
            logging.info(f"Correo de confirmación enviado a {email}.")
            return render_template("register.html", info="Se ha enviado un correo de confirmación. Tienes 5 minutos para confirmar el registro.")
        else:
            logging.error(f"Error al enviar correo: {response}")
            return render_template("register.html", error="Error al enviar el correo de confirmación.")

    return render_template("register.html")


route = re.sub(r"^(\/).*", r"\1login", route)
@app.route(route, methods=["GET", "POST"])
def login():
    # Ruta de inicio de sesión
    if "username" in session:
        return redirect(url_for("home"))

    # Al recibir el cuestionario
    if request.method == "POST":
        if request.form.get("form_id") == "loginForm":
            # Recibe los datos del cuestionario y comprueba si el usuario está registrado
            dni_or_username_or_email = request.form["username_or_email"].lower()
            password = request.form["password"]

            type = users_db.identifier_type(dni_or_username_or_email)
            if type == "DNI" or type == "email":
                identifier = security.make_search_index(dni_or_username_or_email, SECRET_KEY)
            else:
                identifier = dni_or_username_or_email
            user = users_db.check_user(identifier, type)

            if user is not False:
                # Recupera el salt y verifica si la contraseña es correcta
                stored_password = user["password"]
                salt = base64.urlsafe_b64decode(user["salt"])
                if security.verify_password(stored_password, salt, password):
                    route = user["certificate"]
                    # Si es correcta, recupera el certificado
                    if route != "" and route is not None:
                        # Se comprueba si el certificado es válido
                        if security.verify_certificate(route):
                            session["username"] = user["name"]
                            session["role"] = user["role"]

                            private_key = security.decrypt_private_key(user["private_key"], password, salt)
                            private_key = security.serialize_private_key(private_key)
                            session["private_key"] = private_key

                            session.permanent = True
                            logging.info(f"Usuario {dni_or_username_or_email} ha iniciado sesión.")
                            return redirect(url_for("home"))
                        else:
                            # Si el certificado no es válido, se revoca y se crea un nuevo request con los mismos datos
                            public_key = security.get_public_key_from_certificate(route)
                            private_key = security.decrypt_private_key(user["private_key"], password, salt)
                            security.create_request(user["name"], public_key , private_key)

                            logging.error(f"Certificado alterado o caducado para {dni_or_username_or_email}.")
                            error = "Ha habido un error con su certificado, debe esperar a que sea aprobado en el sistema nuevamente"
                            return render_template("login.html", error=error)
                    else:
                        # Si directamente no existe una ruta para acceder al certificado puede ser que esté en espera
                        logging.error(f"Certificado en espera o no aceptado para {dni_or_username_or_email}.")
                        error = "Debe esperar a que sea aprobado en el sistema."
                        return render_template("login.html", error=error)
                else:
                    # Si los datos de contraseña son incorrectos
                    logging.error(f"Intento fallido de inicio de sesión para {dni_or_username_or_email}.")
                    error = "Usuario o contraseña incorrecta o la cuenta no existe"
                    return render_template("login.html", error=error)
            else:
                # Si los datos de usuario son incorrectos (exactamente el mismo mensaje que para la contraseña para no dar indicios)
                logging.error(f"Intento fallido de inicio de sesión para {dni_or_username_or_email}.")
                error = "Usuario o contraseña incorrecta o la cuenta no existe"
                return render_template("login.html", error=error)
    else:
        return render_template("login.html")


route = re.sub(r"^(\/).*", r"\1home", route)
@app.route(route, methods=["GET", "POST"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))
 
    username = session["username"]

    if request.method == "POST":
        if "search_form" in request.form:
            user_searched_input = request.form["user_searched"].strip()
            user_searched_data  = users_db.check_user(user_searched_input, "name")

            if user_searched_data:
                session["found"]        = True
                session["user_searched"] = user_searched_data["name"]
            else:
                session["found"]        = False
                session["user_searched"] = None

            return redirect(url_for("home"))
        
        # Manejar eliminación de encuestas
        if "delete_survey" in request.form:
            survey_id = request.form.get("survey_id")
            survey = survey_db.get_survey(int(survey_id))
            
            # Verificar que el usuario es el creador
            if survey and survey["creator_id"] == username:
                survey_db.delete_survey(int(survey_id))
                logging.info(f"Encuesta '{survey['title']}' eliminada por {username}.")
                session["message"] = "Encuesta eliminada correctamente."
            
            return redirect(url_for("home"))
 
    # ── Datos para el template ────────────────────────────────────
    user_surveys  = survey_db.get_user_surveys(username)
 
    found         = session.get("found")
    user_searched = session.get("user_searched")
    found_surveys = []
    voted_ids     = set()
    message       = session.pop("message", None)
 
    if found and user_searched:
        found_surveys = survey_db.get_public_surveys(user_searched)
        if not found_surveys:
            message = f"El usuario '{user_searched}' no tiene encuestas públicas."
        # Marcar qué encuestas ya ha votado el usuario actual
        for s in found_surveys:
            user_hash = security.generate_user_hash(s["id"], username, SECRET_KEY)
            if survey_db.has_voted(s["id"], user_hash):
                voted_ids.add(s["id"])
    elif found is False:
        message = "El usuario no existe."
 
    return render_template("home.html",
        username      = username,
        role          = session["role"],
        user_surveys  = user_surveys,
        found         = found,
        user_searched = user_searched,
        found_surveys = found_surveys,
        voted_ids     = voted_ids,
        message       = message,
    )



# PÁGINA EXCLUSIVA PARA ADMINS: Acceder a la lista de usuarios
route = re.sub(r"^(\/).*", r"\1users", route)
@app.route(route, methods=["GET", "POST"])
def list_users():
    # Ruta de lista de usuarios
    if "username" not in session:
        abort(404)
    
    if session["role"] != "admin":
        abort(404)

    # Función para eliminar un usuario
    if request.method == "POST" and "delete" in request.form:
        user_deleted = request.form.get("username")
        # TODO Quitar para mensajes
        # messages_db.remove_messages(user_deleted)
        users_db.remove_user(user_deleted)
        logging.info("El usuario se ha eliminado de la tabla de datos correctamente.")

    # Función para ascender un usuario a Admin
    if request.method == "POST" and "promote" in request.form:
        user_promoted = request.form.get("username")
        users_db.promote_user(user_promoted)
    
    users = users_db.list_users()

    return render_template("users.html", users=users)


# PÁGINA EXCLUSIVA PARA ADMINS: Acceder a la lista de mensajes
# TODO Quitar para mensajes
"""route = re.sub(r"^(\/).*", r"\1messages", route)
@app.route(route, methods=["GET", "POST"])
def list_messages():
    # Ruta de lista de mensajes
    if "username" not in session:
        abort(404)
    
    if session["role"] != "admin":
        abort(404)
    
    messages = messages_db.list_messages()
    messages_list = []

    for m in messages:
        messages_list.append(dict(m))

    # Para descifrar mensaje (solo para enseñar en la defensa)
    if request.method == "POST":
        message_id = request.form.get("id")
        message = messages_db.get_message(message_id)
        private_key = security.deserialize_private_key(session["private_key"])

        user = users_db.check_user(session["username"], "name")
        route = user["certificate"]
        public_key = security.get_public_key_from_certificate(route)

        message = security.check_messages(message, session["username"], public_key, private_key)

        if message != "error":
            for m in messages_list:
                if int(m["id"]) == int(message_id):
                    m["text"] = message[0][2]
        
        return render_template("messages.html", messages=messages_list)
    
    return render_template("messages.html", messages=messages_list)"""


# Página para acceder a tu propio perfil
route = re.sub(r"^(\/).*", r"\1/profile", route)
@app.route(route, methods=["GET", "POST"])
def profile():
    # Ruta de perfil de usuario
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        user = users_db.check_user(session["username"], "name")
        username = user["name"]

        # Función para cambiar la contraseña (con verificación de contraseña)
        if request.method == "POST" and "change_password" in request.form:
            password = request.form["password"]
            new_password = request.form["new_password"]
            new_password2 = request.form["new_password2"]
            stored_password = user["password"]
            salt = base64.urlsafe_b64decode(user["salt"])

            if not security.verify_password(stored_password, salt, password):
                error = "La contraseña no es correcta"
                return render_template("profile.html", username=username, error=error)
            
            if not security.check_password(new_password):
                error = ("La contraseña es inválida. Debe tener al menos 6 "
                        "caracteres, una mayúscula, una minúscula, un número y "
                        "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                        "espacios.")
                return render_template("profile.html", username=username, error=error)
            
            if new_password != new_password2:
                error = "Las contraseñas no coinciden"
                return render_template("profile.html", username=username, error=error)
            

            private_key = user["private_key"]
            private_key = security.decrypt_private_key(private_key, password, salt)
            private_key = security.encrypt_private_key(private_key, new_password, salt)

            hashed_password = security.hash(new_password, salt)
            users_db.update_password(username, hashed_password, private_key)
            success = "Las contraseña ha sido actualizada correctamente"

            return render_template("profile.html", username=username, success=success)

        # Función para eliminar el usuario
        if request.method == "POST" and "delete_account" in request.form:
            # TODO Quitar para mensajes
            #messages_db.remove_messages(session["username"])
            users_db.remove_user(session["username"])
            session.clear()
            return redirect(url_for("index"))
        
        return render_template("profile.html", username=username)


route = re.sub(r"^(\/).*", r"\1/logout", route)
@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Cerrado de sesión
    if request.method == "GET":
        abort(404)
    else:
        session.clear()
        return redirect(url_for("index"))


@app.route("/authorize")
def authorize():
    with open("./config/client_secret.json") as f:
        config = json.load(f)["web"]

    # La redirect_uri debe coincidir EXACTAMENTE con la de Google Cloud Console
    redirect_uri = config["redirect_uris"][0]

    auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code"
        "&scope=https://www.googleapis.com/auth/gmail.send"
        "&access_type=offline"
        "&prompt=consent"
    )
    return redirect(auth_url)


@app.route("/oauth2callback", methods=["GET"])
def oauth2callback():
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        logging.error(f"OAuth error: {error}")
        return f"Error OAuth: {error}", 400

    if not code:
        return "No se recibió código de autorización", 400

    with open("./config/client_secret.json") as f:
        config = json.load(f)["web"]

    redirect_uri = config["redirect_uris"][0]

    response = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    })

    if response.status_code != 200:
        logging.error(f"Error al obtener token: {response.text}")
        return f"Error al obtener token: {response.text}", 400

    token_data = response.json()
    token_data["expires_at"] = time.time() + token_data.get("expires_in", 3600)

    with open("./config/token_store.json", "w") as f:
        json.dump(token_data, f, indent=2)

    logging.info("Token OAuth2 guardado correctamente.")
    return redirect(url_for("index"))

@app.route("/confirm/<token>")
def confirm_register(token):
    data = pending_registrations.get(token)

    if not data:
        return render_template("register.html", error="Enlace inválido o ya utilizado.")

    if time.time() > data["expires_at"]:
        pending_registrations.pop(token, None)
        return render_template("register.html", error="El enlace ha caducado. Vuelve a registrarte.")

    # Guardar usuario ahora
    result = users_db.add_user(
        data["DNI"],
        data["DNI_search"],
        data["name"],
        data["email"],
        data["email_search"],
        data["hashed_password"],
        data["salt"],
        data["private_key"]
    )

    pending_registrations.pop(token, None)

    if result:
        logging.info(f"Usuario {data['name']} registrado tras confirmación por email.")
        return redirect(url_for("login"))
    else:
        return render_template("register.html", error="Usuario o email ya registrados.")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = request.form["identifier"].strip()
        type = users_db.identifier_type(identifier)
        if type == "DNI" or type == "email":
            identifier = security.make_search_index(identifier, SECRET_KEY)  # HMAC, no encrypt
        user = users_db.check_user(identifier, type)

        success = "Si el usuario existe, recibirás un correo con las instrucciones."

        if user:
            token = secrets.token_urlsafe(32)
            reset_tokens[token] = {
                "name": user["name"],
                "expires_at": time.time() + 300
            }
            reset_url = f"{request.host_url}reset_password/{token}"

            from_email = '"AGULE - Recuperación de contraseña" <mariohidtfg@gmail.com>'
            to_email = security.decrypt_field(user["email_search"], SECRET_KEY)
            subject = "Recuperación de contraseña - AGULE"
            body = (
                f"Hola, {user["name"]}\n\n"
                f"Hemos recibido una solicitud para cambiar la contraseña de tu cuenta.\n\n"
                f"Haz clic en el siguiente enlace para establecer una nueva contraseña:\n\n"
                f"{reset_url}\n\n"
                f"Este enlace expirará en 5 minutos.\n\n"
                f"Si no has solicitado este cambio, ignora este mensaje."
            )
            try:
                security.send_email_gmail_api(from_email, to_email, subject, body)
            except Exception as e:
                logging.error(f"Error enviando correo de recuperación: {e}")

        return render_template("forgot_password.html", success=success)

    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_data = reset_tokens.get(token)
    if not token_data or time.time() > token_data["expires_at"]:
        return render_template("reset_password.html",
                               error="El enlace ha caducado o no es válido.",
                               token=None)

    if request.method == "POST":
        new_password = request.form["new_password"]
        new_password2 = request.form["new_password2"]

        if not security.check_password(new_password):
            error = ("La contraseña es inválida. Debe tener al menos 6 caracteres, "
                     "una mayúscula, una minúscula, un número y un carácter especial "
                     "($!%*?&_¿@#=-). No puede incluir espacios.")
            return render_template("reset_password.html", error=error, token=token)

        if new_password != new_password2:
            return render_template("reset_password.html",
                                   error="Las contraseñas no coinciden.", token=token)

        # Buscar usuario por el índice DNI guardado en el token
        user = users_db.check_user(token_data["name"], "name")
        if not user:
            return render_template("reset_password.html",
                                   error="Error al procesar la solicitud.", token=None)

        # Calcular nueva contraseña y nueva clave privada
        salt = base64.urlsafe_b64decode(user["salt"])
        hashed_password = security.hash(new_password, salt)
        private_key, public_key = security.generate_keys()
        security.create_request(user["name"], public_key, private_key)
        private_key_encrypted = security.encrypt_private_key(private_key, new_password, salt)

        users_db.update_password_reset(user["name"], hashed_password, private_key_encrypted)
        del reset_tokens[token]

        logging.info(f"Contraseña restablecida para {user['name']}.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

def load_questions_with_options(survey_id):
    """Carga las preguntas de una encuesta e incluye sus opciones."""
    questions = questions_db.list_questions(survey_id)
    questions_list = []
    for question in questions:
        question_dict = dict(question)
        if question_dict["type"] in ["s", "m"]:
            question_dict["options"] = questionOptions_dn.list_options(question_dict["id"])
        else:
            question_dict["options"] = []
        questions_list.append(question_dict)
    return questions_list

@app.route("/create_survey", methods=["GET", "POST"])
def create_survey():
    if "username" not in session:
        return redirect(url_for("login"))
    
    username = session["username"]
    survey_id = request.args.get("survey_id")
    survey = None
    questions = []
    
    if survey_id:
        survey = survey_db.get_survey(int(survey_id))
        if not survey or survey["creator_id"] != username:
            abort(403)
        questions = load_questions_with_options(int(survey_id))
    
    if request.method == "POST":
        if "create_survey" in request.form:
            title       = request.form.get("survey_title", "").strip()
            description = request.form.get("survey_description", "").strip()
            start_at    = request.form.get("start_at", "").strip()
            end_at      = request.form.get("end_at", "").strip()
            is_public   = request.form.get("is_public", "n")

            if not title:
                return render_template("create_survey.html", username=username, survey_id=None, 
                    error="El título de la encuesta es obligatorio.")
            
            # Validar que start_at < end_at si ambas están presentes
            if start_at and end_at:
                try:
                    from datetime import datetime
                    start = datetime.fromisoformat(start_at)
                    end = datetime.fromisoformat(end_at)
                    if start >= end:
                        return render_template("create_survey.html", username=username, survey_id=None,
                            error="La fecha de inicio debe ser anterior a la fecha de fin.")
                except ValueError:
                    pass
            
            new_survey_id = survey_db.add_survey(username, title, description, start_at, end_at, is_public)
            
            if new_survey_id:
                logging.info(f"Encuesta '{title}' creada por {username}.")
                return redirect(url_for("create_survey", survey_id=new_survey_id))
        
        # Agregar pregunta a la encuesta
        if "add_question" in request.form:
            if not survey_id:
                return render_template("create_survey.html", username=username, survey_id=None,
                    error="Primero debes crear una encuesta.")
            
            question_title = request.form.get("question_title", "").strip()
            question_type  = request.form.get("question_type", "t")  # t: text, n: numeric, s: single, m: multiple
            is_demographic = request.form.get("is_demographic") is not None
            options = [o.strip() for o in request.form.getlist("options[]") if o.strip()]
            
            # El título es obligatorio solo si quieres agregar la pregunta
            if not question_title:
                questions = load_questions_with_options(int(survey_id))
                return render_template("create_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="El título de la pregunta es obligatorio.")
            
            # Para preguntas de opción única o múltiple, se requieren opciones
            if question_type in ["s", "m"] and not options:
                questions = load_questions_with_options(int(survey_id))
                return render_template("create_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="Las preguntas de opción requieren al menos una opción.")
            
            question_id = questions_db.add_question(int(survey_id), is_demographic, question_title, question_type)
            
            if question_id:
                # Agregar opciones si existen
                if question_type in ["s", "m"]:
                    for option_text in options:
                        questionOptions_dn.add_option(question_id, option_text)
                
                logging.info(f"Pregunta '{question_title}' agregada a encuesta {survey_id} por {username}.")
                questions = load_questions_with_options(int(survey_id))
                return render_template("create_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, info="Pregunta agregada correctamente.")
        
        # Actualizar pregunta
        if "update_question" in request.form:
            question_id = request.form.get("question_id")
            edit_title = request.form.get("edit_question_title", "").strip()
            edit_type = request.form.get("edit_question_type", "t")
            edit_is_demographic = request.form.get("edit_is_demographic") is not None
            
            if not edit_title:
                questions = load_questions_with_options(int(survey_id))
                return render_template("create_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="El título de la pregunta es obligatorio.")
            
            questions_db.update_question(int(question_id), edit_title, edit_type, edit_is_demographic)
            
            # Manejar opciones si es una pregunta de múltiple opción
            if edit_type in ["s", "m"]:
                edit_options = request.form.getlist("edit_options[]")
                edit_option_ids = request.form.getlist("edit_option_ids[]")
                
                # Actualizar/crear opciones
                for option_text, option_id in zip(edit_options, edit_option_ids):
                    option_text = option_text.strip()
                    if option_text:
                        if option_id:
                            # Actualizar opción existente
                            questionOptions_dn.update_option(int(option_id), option_text)
                        else:
                            # Crear nueva opción
                            questionOptions_dn.add_option(int(question_id), option_text)
            
            logging.info(f"Pregunta actualizada en encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(int(survey_id))
            return render_template("create_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Pregunta actualizada correctamente.")
        
        # Eliminar pregunta
        if "delete_question" in request.form:
            question_id = request.form.get("question_id")
            questions_db.remove_question(int(question_id))
            logging.info(f"Pregunta eliminada de encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(int(survey_id))
            return render_template("create_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Pregunta eliminada correctamente.")
        
        # Reordenar preguntas
        if "reorder_questions" in request.form:
            question_order = request.form.get("question_order", "")
            if question_order:
                question_ids = [int(qid) for qid in question_order.split(',') if qid.isdigit()]
                # Actualizar posiciones
                for position, qid in enumerate(question_ids, start=1):
                    questions_db.update_question_position(qid, position)
                logging.info(f"Preguntas reordenadas en encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(int(survey_id))
            return render_template("create_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Orden actualizado.")
            return render_template("create_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Pregunta eliminada correctamente.")
        
        # Cancelar (volver a home)
        if "cancel" in request.form:
            return redirect(url_for("home"))
    
    if questions:
        questions = load_questions_with_options(int(survey_id))
    
    return render_template("create_survey.html", username=username, survey_id=survey_id,
        survey=dict(survey) if survey else None, questions=questions, error=None, info=None)


# TODO Este int debe cambiarse por un hash random
@app.route("/edit_survey/<int:survey_id>", methods=["GET", "POST"])
def edit_survey(survey_id):
    if "username" not in session:
        return redirect(url_for("login"))
    
    username = session["username"]
    survey = survey_db.get_survey(survey_id)
    
    if not survey:
        abort(404)
    
    if survey["creator_id"] != username and not surveyAdmins_db.is_admin(survey_id, username):
        abort(403)
    
    questions = load_questions_with_options(survey_id)
    
    if request.method == "POST":
        # Editar fechas de la encuesta
        if "edit_survey" in request.form:
            start_at = request.form.get("start_at", "").strip()
            end_at   = request.form.get("end_at", "").strip()
            
            # Validar que start_at < end_at si ambas están presentes
            if start_at and end_at:
                try:
                    from datetime import datetime
                    start = datetime.fromisoformat(start_at)
                    end = datetime.fromisoformat(end_at)
                    if start >= end:
                        questions = load_questions_with_options(survey_id)
                        return render_template("edit_survey.html", username=username, survey_id=survey_id,
                            survey=dict(survey), questions=questions, error="La fecha de inicio debe ser anterior a la fecha de fin.")
                except ValueError:
                    pass
            
            survey_db.modify_dates(survey_id, start_at, end_at)
            logging.info(f"Encuesta {survey_id} editada por {username}.")
            questions = load_questions_with_options(survey_id)
            return render_template("edit_survey.html", username=username, survey_id=survey_id, 
                survey=dict(survey), questions=questions, info="Encuesta actualizada correctamente.")
        
        # Agregar pregunta a la encuesta
        if "add_question" in request.form:
            question_title = request.form.get("question_title", "").strip()
            question_type  = request.form.get("question_type", "t")
            is_demographic = request.form.get("is_demographic") is not None
            options = [o.strip() for o in request.form.getlist("options[]") if o.strip()]
            
            if not question_title:
                questions = load_questions_with_options(survey_id)
                return render_template("edit_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="El título de la pregunta es obligatorio.")
            
            if question_type in ["s", "m"] and not options:
                questions = load_questions_with_options(survey_id)
                return render_template("edit_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="Las preguntas de opción requieren al menos una opción.")
            
            question_id = questions_db.add_question(survey_id, is_demographic, question_title, question_type)
            
            if question_id:
                if question_type in ["s", "m"]:
                    for option_text in options:
                        questionOptions_dn.add_option(question_id, option_text)
                
                logging.info(f"Pregunta '{question_title}' agregada a encuesta {survey_id} por {username}.")
                questions = load_questions_with_options(survey_id)
                return render_template("edit_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, info="Pregunta agregada correctamente.")
        
        # Actualizar pregunta
        if "update_question" in request.form:
            question_id = request.form.get("question_id")
            edit_title = request.form.get("edit_question_title", "").strip()
            edit_type = request.form.get("edit_question_type", "t")
            edit_is_demographic = request.form.get("edit_is_demographic") is not None
            
            if not edit_title:
                questions = load_questions_with_options(survey_id)
                return render_template("edit_survey.html", username=username, survey_id=survey_id,
                    survey=dict(survey), questions=questions, error="El título de la pregunta es obligatorio.")
            
            questions_db.update_question(int(question_id), edit_title, edit_type, edit_is_demographic)
            
            # Manejar opciones
            if edit_type in ["s", "m"]:
                edit_options = request.form.getlist("edit_options[]")
                edit_option_ids = request.form.getlist("edit_option_ids[]")
                
                for option_text, option_id in zip(edit_options, edit_option_ids):
                    option_text = option_text.strip()
                    if option_text:
                        if option_id:
                            questionOptions_dn.update_option(int(option_id), option_text)
                        else:
                            questionOptions_dn.add_option(int(question_id), option_text)
            
            logging.info(f"Pregunta actualizada en encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(survey_id)
            return render_template("edit_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Pregunta actualizada correctamente.")
        
        # Eliminar pregunta
        if "delete_question" in request.form:
            question_id = request.form.get("question_id")
            questions_db.remove_question(int(question_id))
            logging.info(f"Pregunta eliminada de encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(survey_id)
            return render_template("edit_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Pregunta eliminada correctamente.")
        
        # Reordenar preguntas
        if "reorder_questions" in request.form:
            question_order = request.form.get("question_order", "")
            if question_order:
                question_ids = [int(qid) for qid in question_order.split(',') if qid.isdigit()]
                for position, qid in enumerate(question_ids, start=1):
                    questions_db.update_question_position(qid, position)
                logging.info(f"Preguntas reordenadas en encuesta {survey_id} por {username}.")
            questions = load_questions_with_options(survey_id)
            return render_template("edit_survey.html", username=username, survey_id=survey_id,
                survey=dict(survey), questions=questions, info="Orden actualizado.")
        
        # Eliminar encuesta completa
        if "delete_survey" in request.form:
            survey_db.delete_survey(survey_id)
            logging.info(f"Encuesta {survey_id} eliminada por {username}.")
            return redirect(url_for("home"))
        
        # Cancelar
        if "cancel" in request.form:
            return redirect(url_for("home"))
    
    return render_template("edit_survey.html", username=username, survey_id=survey_id, 
        survey=dict(survey), questions=questions, error=None, info=None)


# TODO Lo mismo que en edit_survey con lo del hash
@app.route("/vote_survey/<int:survey_id>", methods=["GET", "POST"])
def vote_survey(survey_id):
    if "username" not in session:
        return redirect(url_for("login"))
    
    username = session["username"]
    survey = survey_db.get_survey(survey_id)
    
    if not survey:
        abort(404)
    
    # Generar user_hash para esta encuesta
    user_hash = security.generate_user_hash(survey_id, username, SECRET_KEY)
    
    # Verificar si el usuario ya ha votado
    already_voted = survey_db.get_user_submitted_answer(user_hash) is not None
    
    questions = questions_db.list_questions(survey_id)
    options_by_question = {}
    for q in questions:
        options_by_question[q["id"]] = questionOptions_dn.list_options(q["id"])
    
    if request.method == "POST":
        # Cancelar (volver a home)
        if "cancel" in request.form:
            return redirect(url_for("home"))
        
        # Al hacer clic en una opción, guardar automáticamente
        if "vote_option" in request.form and not already_voted:
            # Crear submitted_answer
            demographic_group = None  # Se puede obtener de request.form si existe
            submitted_answer_id = submittedAnswers_db.add_submitted_answer(
                int(survey_id), user_hash, demographic_group)
            
            if submitted_answer_id:
                # Guardar respuestas para cada pregunta
                for question in questions:
                    question_id = question["id"]
                    option_key = f"vote_option_{question_id}"
                    answer_value = request.form.get(option_key)
                    
                    if answer_value:
                        if question["type"] in ["s", "m"]:  # single or multiple choice
                            answers_db.add_answer(submitted_answer_id, question_id, int(answer_value), None)
                        else:  # text or numeric
                            answers_db.add_answer(submitted_answer_id, question_id, None, answer_value)
                
                logging.info(f"{username} votó en encuesta {survey_id}.")
                return redirect(url_for("home"))
    
    return render_template("vote_survey.html", 
        username=username, 
        survey_id=survey_id, 
        survey=dict(survey),
        questions=questions,
        options_by_question=options_by_question,
        already_voted=already_voted,
        error=None)


if __name__ == "__main__":
    # Para muestra en la defensa se ha creado un certificado autofirmado para que la web aparezca como insegura
    app.run(ssl_context=("config/cert.pem", "config/key.pem"), debug=True)

    # Si se desea quitar:
    # app.run(debug=True)
