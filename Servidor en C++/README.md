
## Estructura de Directorios (Sugerida)

Se recomienda organizar los ficheros de la siguiente manera (ajusta según tu estructura real):

ssdd_proyecto_100495833_100495801/
|-- client.py                       # Cliente P2P
|-- test.py                      # Servicio Web
|-- servidor.cpp                      # Servidor P2P principal (también cliente RPC)
|-- logger.x                        # Definición de la interfaz RPC para el logger
|-- logger_server.cpp                 # Implementación de la lógica del servidor RPC
|-- Makefile                        # Makefile para compilar los componentes en C
|-- README.md                       # Este archivo

## 1. Compilación

Todos los componentes en C se compilan utilizando el `Makefile` proporcionado.

1.  **Navega al directorio raíz del proyecto** en una terminal.
2.  **Ejecuta `make`:**
    make
    
    Este comando realizará los siguientes pasos:
    * Llamará a `rpcgen -C logger.x` para generar los archivos necesarios para RPC (`logger.h`, `logger_clnt.c`, `logger_svc.c`, `logger_xdr.c`).
    * Compilará `servidor.c`, `logger_clnt.c` y `logger_xdr.c` y los enlazará con `-lpthread` y `-ltirpc` para crear el ejecutable `servidor`.
    * Compilará `logger_svc.c` (que contiene el `main` y dispatcher RPC), `logger_server.c` (que contiene tu implementación de `log_operation_1_svc`) y `logger_xdr.c`, y los enlazará con `-ltirpc` para crear el ejecutable `logger_serverd`.

3.  **Para limpiar** los archivos objeto (`.o`), los ejecutables y los archivos generados por `rpcgen`, ejecuta:
    make clean

## 2. Despliegue y Ejecución

El sistema consta de varios procesos que deben ejecutarse, preferiblemente cada uno en una terminal separada. El orden de inicio es importante.

**Asunciones para los ejemplos de ejecución:**
* Todos los componentes se ejecutan en la misma máquina (`localhost`).
* El servicio de timestamp usará el puerto `5000`.
* El servidor P2P principal usará el puerto indicado en el flag -p.

**Paso 1: Iniciar el Servidor RPC de Logging (`logger_serverd`)**

* Abre una terminal.
* Navega al directorio del proyecto.
* Ejecuta:
    ./logger_serverd

* Este servidor permanecerá a la espera de peticiones RPC para registrar logs.

**Paso 2: Iniciar el Servicio Web de Timestamp**

* Abre una segunda terminal.
* Navega al directorio del proyecto.
* Ejecuta:
    python3 test.py

* Este servicio comenzará a escuchar.

**Paso 3: Iniciar el Servidor P2P Principal (`servidor`)**

* Abre una tercera terminal.
* Navega al directorio del proyecto.
* **Establece la variable de entorno `LOG_RPC_IP`**:
    export LOG_RPC_IP=localhost

* Ejecuta el servidor P2P:
    ./servidor -p 8080
    
* Deberías ver mensajes indicando que el servidor P2P se ha iniciado y que ha intentado/logrado conectar con el servidor RPC de logging.

**Paso 4: Iniciar el/los Cliente(s) P2P (`client.py`)**

* Abre una o más terminales nuevas (una por cada cliente).
* Navega al directorio del proyecto.
* Ejecuta el cliente, apuntando al servidor P2P (reemplaza `8080` si es diferente):
    python3 client.py -s localhost -p 8080
    
* El cliente mostrará su prompt `c>`. Ahora puedes usar los comandos definidos:
    * `SEND <int> <string>`

---


* TLDR
* Terminal 1:
    ./servidor
* Terminal 2:
    ./python3 test.py