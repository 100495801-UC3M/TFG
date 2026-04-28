# CONFIGURACIÓN GLOBAL

CPP_SEAL_DIR   = cpp/seal
CPP_SERVER_DIR = cpp/server
SEAL_VERSION   = v4.1.1
SEAL_REPO      = https://github.com/microsoft/SEAL.git
SEAL_DIR       = $(CPP_SEAL_DIR)/SEAL
SEAL_BUILD     = $(SEAL_DIR)/build
PROJECT_BUILD  = $(CPP_SEAL_DIR)/build

CC  = gcc
CXX = g++

CMAKE_FLAGS = -DSEAL_BUILD_DEPS=ON \
              -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF \
              -DCMAKE_BUILD_TYPE=Release

# TARGET POR DEFECTO

all: seal server

# DEPENDENCIAS
deps:
	@echo "Instalando dependencias del sistema..."
	@echo "  ⚠  Ejecuta este target con sudo: sudo make deps"
	apt install -y build-essential gcc g++ make cmake git

# SEAL
seal:
	@if [ ! -f "$(SEAL_DIR)/CMakeLists.txt" ]; then \
		echo "Clonando SEAL $(SEAL_VERSION) en $(SEAL_DIR)..."; \
		rm -rf "$(SEAL_DIR)"; \
		git clone --branch $(SEAL_VERSION) $(SEAL_REPO) "$(SEAL_DIR)"; \
	else \
		echo "SEAL ya clonado. Saltando clone."; \
	fi
	@if [ ! -f "$(SEAL_BUILD)/CMakeCache.txt" ]; then \
		echo "Compilando SEAL $(SEAL_VERSION)..."; \
		mkdir -p "$(SEAL_BUILD)"; \
		cd "$(SEAL_BUILD)" && \
		CC=$(CC) CXX=$(CXX) cmake $(CMAKE_FLAGS) .. && \
		make -j$$(nproc); \
	else \
		echo "SEAL ya compilado. Saltando build."; \
	fi
	@$(MAKE) seal-install
	

seal-install:
	@if [ ! -f "/usr/local/lib/cmake/SEAL-4.1/SEALConfig.cmake" ]; then \
		echo "SEAL no instalado. Instalando..."; \
		echo "  ⚠  Si falla, ejecuta con sudo:  sudo make seal-install"; \
		cmake --install "$(SEAL_BUILD)"; \
		echo "SEAL instalado correctamente."; \
	else \
		echo "SEAL ya instalado. Saltando install."; \
	fi



# PROYECTO CMAKE
server:
	@echo "Compilando proyecto CMake..."
	CC=$(CC) CXX=$(CXX) cmake -S "$(CPP_SEAL_DIR)" -B "$(PROJECT_BUILD)"
	cmake --build "$(PROJECT_BUILD)" -j$$(nproc)
	@echo "Proyecto compilado. Binarios en $(PROJECT_BUILD)/"

# EJECUTAR
run-server:
	@echo "Iniciando servidor SEAL completo..."
	"$(PROJECT_BUILD)/servidor_seal"


# CLEAN
clean-server:
	rm -rf "$(PROJECT_BUILD)"
	@echo "Build del server eliminado."

clean-seal:
	rm -rf "$(SEAL_BUILD)"
	@echo "Build de SEAL eliminado."

clean-seal-all: clean-seal
	rm -rf "$(SEAL_DIR)"
	@echo "Repositorio de SEAL eliminado."

clean: clean-server clean-seal
	@echo "Todo limpio menos el repositorio SEAL."

clean-all: clean clean-seal-all
	@echo "Todo limpio."

.PHONY: all deps seal seal-install build run-server run-test run-test-server clean clean-seal clean-all