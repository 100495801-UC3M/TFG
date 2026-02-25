
El entorno virtual en Linux que usaré es WSL. Esto es para simular que el servidor se encuentra en Linux mientras los clientes usan Windows o cualquier otro sistema operativo.


Guía provista por:
https://learn.microsoft.com/es-es/windows/wsl/install


## Para instalar WSL:

Windows Powershell >
wsl --install Ubuntu

wsl.exe --set-default-version 2


### Para abrir WSL e instalar las dependencias (gcc, g++, make, rpcgen):

wsl.exe

sudo apt update

sudo apt install -y build-essential gcc g++ make libtirpc-dev cmake libboost-all-dev libprotobuf-dev protobuf-compiler python3 gcc-9 g++-9 clang

sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100

### Compilar SEAL:

git clone --branch v3.6.6 https://github.com/microsoft/SEAL.git
cd SEAL
mkdir build
cd build
sudo CC=gcc-9 CXX=g++-9 cmake -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF ..
make -j
sudo make install

### Para compilar CMake en seal
cd ../.. //*o la carpeta donde se localiza seal, si no partes desde eva*
CC=gcc-9 CXX=g++-9 cmake -S . -B build
cmake -S . -B build
cmake --build build -j
./build/server


# Make para toda la sección hasta aquí:

## make global (deps, seal y rpc)
make

## o por separado
make deps       # comprobar e instalar prerrequisitos
make seal       # clonar + build SEAL
make rpc        # build RPC
make run-server # abrir servidor
make run-logger # probar test cliente
make run-seal   # probar test seal
make clean      # eliminar todo el build






## Para ejecutar el servidor dentro de WSL:

cd *carpeta donde se localiza el servidor*

make


Y luego seguir con las instrucciones del README.md de la carperta "Servidor en C++".