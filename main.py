import os
import re
import base64
import logging
from datetime import timedelta
import functions
#import app.security as security
#from app.users import Users
#from app.messages import Messages
from flask import Flask, render_template, request, redirect, url_for, session, abort


# Iniciamos el servidor flask
app = Flask(__name__)

# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

# Límite de sesión de 5 minutos
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# Inicializamos las bases de datos
users_db = Users()
account_db = Accounts()

# Configuración logging para que se muestre en la consola
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


route = "/"
@app.route(route)
def index():
    # Ruta de la página de inicio de la web
    return render_template("index.html")


route = re.sub(r"^(\/).*", r"\1register", route)
@app.route(route, methods=["GET", "POST"])
def register():
    # Ruta de registro de usuario
    if "username" in session:
        return redirect(url_for("home"))

    # Al recibir el cuestionario
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        DNI = request.form["DNI"].strip().upper()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        password2 = request.form["password2"]

        #Comprueba que el DNI es válido
        valid = functions.DNI_valid(DNI)
        if valid[0] == False:
            return render_template("register.html", error=valid[1])
            
        # Comprueba que la contraseña es segura
        if not functions.check_password(password):
            error = ("La contraseña es inválida. Debe tener al menos 6 "
                     "caracteres, una mayúscula, una minúscula, un número y "
                     "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                     "espacios.")
            return render_template("register.html", error=error)
        
        if password != password2:
            error = "Las contraseñas no coinciden"
            return render_template("register.html", error=error)

        # Genera un salt para la contraseña
        salt = security.generate_salt_aes("salt", 16)
        hashed_password = security.hash(password, salt)

        # Genera la clave pública y privada
        private_key, public_key = security.generate_keys()

        # Se crea un request de certificado, donde posteriormente se almacenará la clave pública
        security.create_request(username, public_key, private_key)

        # La clave privada es encriptada con la contraseña y el salt
        private_key = security.encrypt_private_key(private_key, password, salt)

        # Guarda en la base de datos los datos del registro
        result = users_db.add_user(username, email, hashed_password, base64.urlsafe_b64encode(salt), private_key)

        if result:
            logging.info(f"Usuario {username} registrado exitosamente.")
            return redirect(url_for("login"))
        else:
            logging.error(f"Error en el registro de {username}. El usuario o el email ya están registrados.")
            error = "Usuario o email ya registrados"
            return render_template("register.html", error=error)
    
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
            username_or_email = request.form["username_or_email"].lower()
            password = request.form["password"]
            user = users_db.check_user(username_or_email)

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
                            session["username"] = user["username"]
                            session["role"] = user["role"]

                            private_key = security.decrypt_private_key(user["private_key"], password, salt)
                            private_key = security.serialize_private_key(private_key)
                            session["private_key"] = private_key

                            session.permanent = True
                            logging.info(f"Usuario {username_or_email} ha iniciado sesión.")
                            return redirect(url_for("home"))
                        else:
                            # Si el certificado no es válido, se revoca y se crea un nuevo request con los mismos datos
                            public_key = security.get_public_key_from_certificate(route)
                            private_key = security.decrypt_private_key(user["private_key"], password, salt)
                            security.create_request(user["username"], public_key , private_key)

                            logging.error(f"Certificado alterado o caducado para {username_or_email}.")
                            error = "Ha habido un error con su certificado, debe esperar a que sea aprobado en el sistema nuevamente"
                            return render_template("login.html", error=error)
                    else:
                        # Si directamente no existe una ruta para acceder al certificado puede ser que esté en espera
                        logging.error(f"Certificado en espera o no aceptado para {username_or_email}.")
                        error = "Debe esperar a que sea aprobado en el sistema"
                        return render_template("login.html", error=error)
                else:
                    # Si los datos de contraseña son incorrectos
                    logging.error(f"Intento fallido de inicio de sesión para {username_or_email}.")
                    error = "Usuario o contraseña incorrectos o la cuenta no existe"
                    return render_template("login.html", error=error)
            else:
                # Si los datos de usuario son incorrectos (exactamente el mismo mensaje que para la contraseña para no dar indicios)
                logging.error(f"Intento fallido de inicio de sesión para {username_or_email}.")
                error = "Usuario o contraseña incorrectos o la cuenta no existe"
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

        user  = users_db.check_user(session["username"])
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
            user_searched_data = users_db.check_user(user_searched_input)
            if user_searched_data:
                # Si existe, devolver la conversación con dicho usuario
                session["found"] = True
                session["user_searched"] = user_searched_data["username"]
                conversations = messages_db.conversations(session["username"], session["user_searched"])
                private_key = security.deserialize_private_key(session["private_key"])

                user = users_db.check_user(session["username"])
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
                receiver = users_db.check_user(user_searched)
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
                sender = users_db.check_user(session["username"])
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

        user = users_db.check_user(session["username"])
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

        user = users_db.check_user(session["username"])
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
        user = users_db.check_user(session["username"])
        username = user["username"]

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


if __name__ == "__main__":
    # Para muestra en la defensa se ha creado un certificado autofirmado para que la web aparezca como insegura
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)

    # Si se desea quitar:
    # app.run(debug=True)
