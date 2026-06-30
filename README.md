
# BIENVENIDO AL README DE AGULE
El entorno virtual en Linux que se usará es WSL. Esto es sirve para simular que el servidor se encuentra en Linux mientras los clientes usan Windows o cualquier otro sistema operativo.

# ARCHIVOS INICIALES
Primero, clona este repositorio en la carpeta local en el que lo quieras mantener.
Después, copia los siguientes archivos que no deben estar subidos a la nube, pero están guardados:

/Code/AC/privado/ca1key.pem                -> Clave privada de la CA para firmar certificados

/Code/config/AC.txt                        -> Contraseña maestra en claro + usuarios registrados

/Code/config/cert.pem                      -> Certificado TLS del servidor Flask

/Code/config/key.pem                       -> Clave privada TLS del servidor Flask

/Code/config/salt.bin                      -> Salt PBKDF2 de la contraseña maestra

Los siguientes archivos se encuentran subidos encriptados. No son necesario copiarlos.

/Code/config/client_secret.json            -> Credenciales OAuth de Google (Gmail API)

/Code/config/token_store.json              -> Token de acceso actual de Gmail

/Code/config/search_secret.key             -> Clave secreta para realizar búsquedas



# INICIO: Instalación y configuración de WSL.

Para la demostración en una única máquina, abriremos dos terminales en la carpeta del proyecto (code).
Una de ellas será la simulación del entorno del servidor de Linux y la otra de Windows.

## Primero, en una terminal, instalamos WSL:

wsl --install Ubuntu

wsl --set-version Ubuntu 2

## Entrar y salir de WSL

### Para entrar a WSL ejecuta:

wsl.exe

### Y para salir ejecuta:

exit

Esto viene bien para realizar el segundo comando del bloque anterior.

# CONFIGURACIÓN APLICACIÓN EN WINDOWS

## Para activar e instalar dependencias del entorno virtual de Windows:

python -m venv .venv_win

.\.venv_win\Scripts\activate

.\.venv_win\Scripts\python.exe -m pip install -r .\requirements.txt

## Para salir del entorno virtual, si fuese necesario, ejecutar:

deactivate

# CONFIGURACIÓN SERVIDOR EN LINUX

## Para activar e instalar dependencias del entorno virtual de Linux, se ejecuta en una terminal con WSL abierto:

sudo apt update

sudo apt install python3.12-venv make

python3 -m venv .venv_lin

source .venv_lin/bin/activate

make deps 

### Si da error con make deps, ejecuta

sudo make deps

# COMPILACIÓN Y ABRIR SERVIDOR

## Si para alguno de estos pasos da error, ejecuta el mismo comando pero con "sudo" delante, como en el anterior.

## Se debe compilar, instalar y activar SEAL y el servidor. Para ello, ejecuta:

make

### Alternativamente, puedes ejecutarlos por separado

make seal

make server

## Para abrir el servidor ejecuta:

make run-server

## Para cerrarlo:

cntrl + C

# ELIMINACIÓN DE ARCHIVOS:

### El servidor

clean-build

### Seal (sin el repositorio)

clean-seal

### Seal (con el repositorio)

clean-seal-all

### El servidor y Seal (sin el repositorio)

clean

### El servidor y Seal (con el repositorio)

clean-all


# EJECUCCIÓN EN WINDOWS


## Para empezar el proyecto

python .\main.py



# Configuración del correo (Gmail API + OAuth2), si se ejecuta por primera vez o si el token ha expirado:

1. Ir a https://console.cloud.google.com:
   - Elegir proyecto existente (TFG)
   - Crear credenciales OAuth 2.0 (*APIs y servicios > Credenciales > Crear credenciales > ID de cliente de OAuth*)
     - Tipo: **Web application**
     - Orígenes autorizados de JavaScript: `https://localhost:5000/authorize`
     - Redirect URI autorizada: `https://localhost:5000/oauth2callback`
   - Descargar el JSON y guardarlo en `./config/client_secret.json`

2. Arrancar el servidor (python .\main.py), visitar en el navegador https://localhost:5000/authorize y
    aceptar los permisos para generar`./config/token_store.json` automáticamente.

4. A partir de aquí el token se refresca solo. No es necesario repetir este proceso
   salvo que se revoque el acceso manualmente o se cambien las credenciales.

### Archivos necesarios en ./config para que funcione bien
- `client_secret.json` — descargado de Google Cloud Console (no subir a git)
- `token_store.json`   — generado automáticamente tras autorizar (no subir a git)

## Script para aceptar los certificados:

cd AC

bash aprobar_solicitudes.sh
