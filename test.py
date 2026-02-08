import os
import re
import base64
import logging
from datetime import timedelta
import app.security as security
from app.users import Users
from app.messages import Messages
from email.mime.text import MIMEText

from_email='"Test de TFG" <mariohidtfg@gmail.com>'
to_email="mariohidtfg@gmail.com"
subject="Correo de prueba"
body="Hola!\nSegundo test enviado."

status, response = security.send_email_gmail_api(from_email, to_email, subject, body)
print(status)
print(response)
