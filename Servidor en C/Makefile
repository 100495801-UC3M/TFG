# Makefile para el Proyecto de Sistemas Distribuidos (Parte 1, 2 y 3)

# Compilador y flags
CC = gcc
CFLAGS = -g -Wall -Wextra 
CFLAGS_RPC_INCLUDE = -I/usr/include/tirpc # Activado si es necesario
CFLAGS_WITH_RPC = $(CFLAGS) $(CFLAGS_RPC_INCLUDE)
LDFLAGS_PTHREAD = -pthread 
RPCLIBS = -ltirpc          # Usar libtirpc directamente

# Herramienta rpcgen
RPCGEN = rpcgen
RPCGENFLAGS = -C # Ya no usamos -a para evitar conflictos con logger_server.c

# Archivo de definición RPC
RPC_DEF_FILE = logger.x

# Archivos generados por rpcgen a partir de logger.x
RPC_HEADER = logger.h
RPC_CLIENT_SRC = logger_clnt.c
RPC_SERVER_SKELETON_SRC = logger_svc.c # Este es el esqueleto principal
RPC_XDR_SRC = logger_xdr.c

RPC_CLIENT_OBJ = logger_clnt.o
RPC_SERVER_SKELETON_OBJ = logger_svc.o # Objeto del esqueleto principal
RPC_XDR_OBJ = logger_xdr.o

# Archivo de implementación del servidor RPC (donde está tu lógica)
RPC_SERVER_IMPL_SRC = logger_server.c # Asumiendo que este es el nombre
RPC_SERVER_IMPL_OBJ = logger_server.o

# Archivos fuente y objeto para el servidor P2P (que es cliente RPC)
SERVER_P2P_SRC = servidor.c
SERVER_P2P_OBJ = servidor.o
TARGET_SERVER_P2P = servidor

# Ejecutable del Servidor RPC de Logging
TARGET_RPC_LOGGER_SERVER = logger_serverd

# Regla por defecto: compilar ambos ejecutables
all: $(TARGET_SERVER_P2P) $(TARGET_RPC_LOGGER_SERVER)

# Regla para generar los archivos RPC desde logger.x
$(RPC_HEADER) $(RPC_CLIENT_SRC) $(RPC_SERVER_SKELETON_SRC) $(RPC_XDR_SRC): $(RPC_DEF_FILE)
	@echo "Generando archivos RPC desde $(RPC_DEF_FILE)..."
	$(RPCGEN) $(RPCGENFLAGS) $(RPC_DEF_FILE) # Solo genera .h, _clnt.c, _svc.c, _xdr.c

# --- Compilación del Servidor P2P (que es cliente RPC) ---
$(SERVER_P2P_OBJ): $(SERVER_P2P_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(SERVER_P2P_SRC) -o $(SERVER_P2P_OBJ) $(LDFLAGS_PTHREAD)

$(RPC_CLIENT_OBJ): $(RPC_CLIENT_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_CLIENT_SRC) -o $(RPC_CLIENT_OBJ)

$(RPC_XDR_OBJ): $(RPC_XDR_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_XDR_SRC) -o $(RPC_XDR_OBJ)

$(TARGET_SERVER_P2P): $(SERVER_P2P_OBJ) $(RPC_CLIENT_OBJ) $(RPC_XDR_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS_PTHREAD) $(RPCLIBS)
	@echo "Servidor P2P '$(TARGET_SERVER_P2P)' compilado."

# --- Compilación del Servidor RPC de Logging ---
# Objeto del esqueleto principal del servidor RPC
$(RPC_SERVER_SKELETON_OBJ): $(RPC_SERVER_SKELETON_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_SERVER_SKELETON_SRC) -o $(RPC_SERVER_SKELETON_OBJ)

# Objeto de la implementación de los procedimientos del servidor RPC
$(RPC_SERVER_IMPL_OBJ): $(RPC_SERVER_IMPL_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_SERVER_IMPL_SRC) -o $(RPC_SERVER_IMPL_OBJ)

# Enlace del Servidor RPC de Logging
$(TARGET_RPC_LOGGER_SERVER): $(RPC_SERVER_SKELETON_OBJ) $(RPC_SERVER_IMPL_OBJ) $(RPC_XDR_OBJ)
	$(CC) $^ -o $@ $(RPCLIBS) # Se enlazan el esqueleto, tu implementación y xdr
	@echo "Servidor RPC de Logging '$(TARGET_RPC_LOGGER_SERVER)' compilado."

# Regla para limpiar
clean:
	@echo "Limpiando archivos generados..."
	rm -f $(TARGET_SERVER_P2P) $(TARGET_RPC_LOGGER_SERVER)
	rm -f *.o 
	rm -f $(RPC_HEADER) $(RPC_CLIENT_SRC) $(RPC_SERVER_SKELETON_SRC) $(RPC_XDR_SRC)
	# No eliminamos logger_server.c porque ahora es un archivo fuente tuyo
	# rm -f Makefile.logger # Ya no se genera si RPCGENFLAGS no tiene -a

.PHONY: all clean