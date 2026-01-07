import os
import re
import base64
import logging
from datetime import timedelta
import app.security as security
from app.users import Users
from app.messages import Messages

email = "example@gmail.com"
message = "Correo recibido con exito"
security.send_email(email, message)