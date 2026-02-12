
El entorno virtual en Linux que usaré es WSL. Esto es para simular que el servidor se encuentra en Linux mientras los clientes usan Windows o cualquier otro sistema operativo.

Para instalar WSL:
Windows Powershell > wsl --install Ubuntu
wsl.exe --set-default-version 2

Para abrir WSL e instalar las dependencias (gcc, g++, make, rpcgen):
Windows Powershell > wsl.exe
sudo apt update
sudo apt install -y build-essential gcc g++ make libtirpc-dev

Para ejecutar el servidor dentro de WSL:
cd *carpeta donde se localiza el servidor*
make

Y luego seguir con las instrucciones del README.md de la carperta "Servidor en C++".