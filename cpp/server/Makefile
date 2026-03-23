# =========================================
# Makefile Servidor con SEAL y RPC
# =========================================

CC = gcc
CXX = g++
CFLAGS = -g -Wall -Wextra
CXXFLAGS = $(CFLAGS) -std=c++17

# RPC include y librerías
CFLAGS_RPC_INCLUDE = -I/usr/include/tirpc
CFLAGS_WITH_RPC = $(CFLAGS) $(CFLAGS_RPC_INCLUDE)
CXXFLAGS_WITH_RPC = $(CXXFLAGS) $(CFLAGS_RPC_INCLUDE)
LDFLAGS_PTHREAD = -pthread
RPCLIBS = -ltirpc

# SEAL (instalado en /usr/local)
CXXFLAGS_WITH_SEAL = $(CXXFLAGS_WITH_RPC) -I/usr/local/include -I/usr/local/include/SEAL-3.6
LDFLAGS_WITH_SEAL = -L/usr/local/lib -lseal-3.6 $(LDFLAGS_PTHREAD)

# Herramienta rpcgen
RPCGEN = rpcgen
RPCGENFLAGS = -C

# Archivo de definición RPC
RPC_DEF_FILE = logger.x

# Archivos generados por rpcgen
RPC_HEADER = logger.h
RPC_CLIENT_SRC = logger_clnt.c
RPC_SERVER_SKELETON_SRC = logger_svc.c
RPC_XDR_SRC = logger_xdr.c

RPC_CLIENT_OBJ = logger_clnt.o
RPC_SERVER_SKELETON_OBJ = logger_svc.o
RPC_XDR_OBJ = logger_xdr.o

# Implementación del servidor RPC
RPC_SERVER_IMPL_SRC = logger_server.cpp
RPC_SERVER_IMPL_OBJ = logger_server.o

# Servidor P2P (cliente RPC)
SERVER_P2P_SRC = servidor.cpp
SERVER_P2P_OBJ = servidor.o
TARGET_SERVER_P2P = servidor

# Servidor RPC de logging
TARGET_RPC_LOGGER_SERVER = logger_serverd

# -------------------
# Regla por defecto
# -------------------
all: $(TARGET_SERVER_P2P) $(TARGET_RPC_LOGGER_SERVER)

# -------------------
# Generar archivos RPC
# -------------------
$(RPC_HEADER) $(RPC_CLIENT_SRC) $(RPC_SERVER_SKELETON_SRC) $(RPC_XDR_SRC): $(RPC_DEF_FILE)
	@echo "Generando archivos RPC desde $(RPC_DEF_FILE)..."
	$(RPCGEN) $(RPCGENFLAGS) $(RPC_DEF_FILE)

# -------------------
# Compilar servidor P2P (cliente RPC)
# -------------------
$(SERVER_P2P_OBJ): $(SERVER_P2P_SRC) $(RPC_HEADER)
	$(CXX) $(CXXFLAGS_WITH_SEAL) -c $(SERVER_P2P_SRC) -o $(SERVER_P2P_OBJ)

$(TARGET_SERVER_P2P): $(SERVER_P2P_OBJ) $(RPC_CLIENT_OBJ) $(RPC_XDR_OBJ)
	$(CXX) $^ -o $@ $(LDFLAGS_WITH_SEAL) $(RPCLIBS)
	@echo "Servidor P2P '$(TARGET_SERVER_P2P)' compilado."

# -------------------
# Compilar RPC client y xdr
# -------------------
$(RPC_CLIENT_OBJ): $(RPC_CLIENT_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_CLIENT_SRC) -o $(RPC_CLIENT_OBJ)

$(RPC_XDR_OBJ): $(RPC_XDR_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_XDR_SRC) -o $(RPC_XDR_OBJ)

# -------------------
# Compilar servidor RPC
# -------------------
$(RPC_SERVER_SKELETON_OBJ): $(RPC_SERVER_SKELETON_SRC) $(RPC_HEADER)
	$(CC) $(CFLAGS_WITH_RPC) -c $(RPC_SERVER_SKELETON_SRC) -o $(RPC_SERVER_SKELETON_OBJ)

$(RPC_SERVER_IMPL_OBJ): $(RPC_SERVER_IMPL_SRC) $(RPC_HEADER)
	$(CXX) $(CXXFLAGS_WITH_SEAL) -c $(RPC_SERVER_IMPL_SRC) -o $(RPC_SERVER_IMPL_OBJ)

$(TARGET_RPC_LOGGER_SERVER): $(RPC_SERVER_SKELETON_OBJ) $(RPC_SERVER_IMPL_OBJ) $(RPC_XDR_OBJ)
	$(CXX) $^ -o $@ $(LDFLAGS_WITH_SEAL) $(RPCLIBS)
	@echo "Servidor RPC '$(TARGET_RPC_LOGGER_SERVER)' compilado."

# -------------------
# Limpiar todo
# -------------------
clean:
	@echo "Limpiando archivos generados..."
	rm -f $(TARGET_SERVER_P2P) $(TARGET_RPC_LOGGER_SERVER)
	rm -f *.o
	rm -f $(RPC_HEADER) $(RPC_CLIENT_SRC) $(RPC_SERVER_SKELETON_SRC) $(RPC_XDR_SRC)

.PHONY: all clean