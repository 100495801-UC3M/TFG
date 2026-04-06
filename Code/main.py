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
from app.messages import Messages
from flask import Flask, render_template, request, redirect, url_for, session, abort


# Iniciamos el servidor flask
app = Flask(__name__)

# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

# Límite de sesión de 5 minutos
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# Inicializamos las bases de datos
users_db = Users()
messages_db = Messages()
pending_registrations = {}
reset_tokens = {}
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
        DNI = request.form["DNI"].strip().upper()
        name = request.form["username"].strip().lower()
        first_surname = request.form["username"].strip().upper()
        second_surname = request.form["username"].strip().upper()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        password2 = request.form["password2"]

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

        salt = security.generate_salt_aes("salt", 16)
        dni_encrypted = security.encrypt_field(DNI, SECRET_KEY)
        email_encrypted = security.encrypt_field(email, SECRET_KEY)
        hashed_password = security.hash(password, salt)
        private_key, public_key = security.generate_keys()
        security.create_request(name, public_key, private_key)
        private_key_encrypted = security.encrypt_private_key(private_key, password, salt)

        # Generar token único con expiración de 5 minutos
        token = str(uuid.uuid4())
        pending_registrations[token] = {
            "DNI": dni_index,
            "DNI_search": dni_encrypted,
            "name": name,
            "first_surname": first_surname,
            "second_surname": second_surname,
            "email": email_index,
            "email_search": email_encrypted,
            "hashed_password": hashed_password,
            "created_at": time.time(),
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "private_key": private_key_encrypted,
            "expires_at": time.time() + 300,  # 5 minutos
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
    # Ruta pricipal de un usuario cuando ha inicia sesión
    if "username" not in session:
        return redirect(url_for("login"))

    # Coger el último mensaje de todas las conversaciones y mostrarlo
    list = []
    list_conversations = messages_db.list_conversations(session["username"])
    for person in list_conversations:
        private_key = security.deserialize_private_key(session["private_key"])
        message = messages_db.get_message(int(person[0]))

        user  = users_db.check_user(session["username"], "name")
        route = user["certificate"]
        public_key = security.get_public_key_from_certificate(route)

        last_message = security.check_messages(message, session["username"], public_key, private_key)
        last_message = last_message[0][2]
        list.append([person[1], last_message])

    # Encontrar un usuario en la barra de búsqueda
    if request.method == "POST":
        if "search_form" in request.form:
            # Comprueba que el usuario está registrado en la base de datos
            user_searched_input = request.form["user_searched"]

            type = users_db.identifier_type(user_searched_input)
            if type == "DNI" or type == "email":
                identifier = security.make_search_index(user_searched_input, SECRET_KEY)
            else:
                identifier = user_searched_input
            user_searched_data = users_db.check_user(identifier, type)

            if user_searched_data:
                # Si existe, devolver la conversación con dicho usuario
                session["found"] = True
                session["user_searched"] = user_searched_data["username"]
                conversations = messages_db.conversations(session["username"], session["user_searched"])
                private_key = security.deserialize_private_key(session["private_key"])

                user = users_db.check_user(session["username"], "name")
                route = user["certificate"]
                public_key = security.get_public_key_from_certificate(route)

                good_messages = security.check_messages(conversations, session["username"], public_key, private_key)
                session["conversations"] = good_messages
            else:
                session["found"] = False
                error = "Usuario no encontrado"
                return render_template("home.html", list_conversations = list, role=session["role"], error=error)
            
            return redirect(url_for("home"))

        # Para enviar un mensaje a un usuario
        elif "send_message" in request.form:
            message = request.form["message"]
            user_searched = session.get("user_searched")
            if user_searched:
                receiver = users_db.check_user(user_searched, "name")
                route = receiver["certificate"]

                # Coge la clave pública del otro usuario
                if route != "" and route is not None:
                    if security.verify_certificate(route):
                        receiver_public_key = security.get_public_key_from_certificate(route)
                    else:
                        error = "El certificado del usuario al que intenta enviar el mensaje no es válido"
                        return render_template("home.html", list_conversations = list, role=session["role"], error=error)
                else:
                    error = "El certificado del usuario al que intenta enviar el mensaje no es válido"
                    return render_template("home.html", list_conversations = list, role=session["role"], error=error)

                # Para enviar un mensaje, se cogen las claves públicas de ambos usuarios
                sender = users_db.check_user(session["username"], "name")
                route = sender["certificate"]
                sender_public_key = security.get_public_key_from_certificate(route)

                # Se crea una clave AES para cifrar el mensaje.
                aes_key = security.generate_salt_aes("aes", 32)
                encrypted_message = security.encrypt_aes_message(message, aes_key)
                hmac = security.generate_hmac(aes_key, encrypted_message)

                # Encriptar la clave AES con la clave pública del emisor y receptor
                encrypted_aes_key_sender = security.encrypt_aes_rsa_key(aes_key, sender_public_key)
                encrypted_aes_key_receiver = security.encrypt_aes_rsa_key(aes_key, receiver_public_key)

                # Coger la clave privada del usuario para firmar el mensaje
                sender_private_key = security.deserialize_private_key(session["private_key"])
                signature = security.sign_message(encrypted_message, hmac, sender_private_key)

                # Enviar el mensaje con ambos usuarios, el mensaje encriptado, hmac, clave aes encriptada por ambas claves públicas y la firma
                if messages_db.send_message(session["username"], user_searched, encrypted_message, hmac, encrypted_aes_key_sender, encrypted_aes_key_receiver, signature):
                    conversations = messages_db.conversations(session["username"], user_searched)
                    good_messages = security.check_messages(conversations, session["username"], sender_public_key, sender_private_key)
                    session["conversations"] = good_messages
                else:
                    error = "Error al enviar el mensaje"
                    return render_template("home.html", list_conversations = list, role=session["role"], error=error)
            else:
                error = "No hay un usuario buscado para enviar el mensaje"
                return render_template("home.html", list_conversations = list, role=session["role"], error=error)
            
            return redirect(url_for("home"))

    if session.get("user_searched") is not None:
        # Escribir en pantalla la conversación con el usuario
        conversations = messages_db.conversations(session["username"], session.get("user_searched"))
        private_key = security.deserialize_private_key(session["private_key"])

        user = users_db.check_user(session["username"], "name")
        route = user["certificate"]

        public_key = security.get_public_key_from_certificate(route)

        good_messages = security.check_messages(conversations, session["username"], public_key, private_key)
        session["conversations"] = good_messages

    user_searched = session.get("user_searched")
    conversations = session.get("conversations")
    found = session.get("found")

    return render_template("home.html", list_conversations = list, username=session["username"], role=session["role"], conversations=conversations, found=found, user_searched=user_searched)


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
        messages_db.remove_messages(user_deleted)
        users_db.remove_user(user_deleted)
        logging.info("El usuario se ha eliminado de la tabla de datos correctamente.")

    # Función para ascender un usuario a Admin
    if request.method == "POST" and "promote" in request.form:
        user_promoted = request.form.get("username")
        users_db.promote_user(user_promoted)
    
    users = users_db.list_users()

    return render_template("users.html", users=users)


# PÁGINA EXCLUSIVA PARA ADMINS: Acceder a la lista de mensajes
route = re.sub(r"^(\/).*", r"\1messages", route)
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
    
    return render_template("messages.html", messages=messages_list)


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
            messages_db.remove_messages(session["username"])
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
        data["first_surname"],
        data["second_surname"],
        data["email"],
        data["email_search"],
        data["hashed_password"],
        data["created_at"],
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
                f"Hola,\n\n"
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
if __name__ == "__main__":
    # Para muestra en la defensa se ha creado un certificado autofirmado para que la web aparezca como insegura
    app.run(ssl_context=("config/cert.pem", "config/key.pem"), debug=True)

    # Si se desea quitar:
    # app.run(debug=True)
