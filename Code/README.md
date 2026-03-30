
El entorno virtual en Linux que se usará es WSL. Esto es sirve para simular que el servidor se encuentra en Linux mientras los clientes usan Windows o cualquier otro sistema operativo.


Guía provista por:
https://learn.microsoft.com/es-es/windows/wsl/install

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
pip install -r .\requirements.txt

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

## Dentro del entorno virtual de Windows, ejecutar:

python .\app\client.py