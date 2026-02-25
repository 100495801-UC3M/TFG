# ===============================
# Configuración
# ===============================

SEAL_VERSION = v3.6.6
SEAL_DIR = SEAL
SEAL_BUILD = $(SEAL_DIR)/build

CC = gcc-9
CXX = g++-9

CMAKE_FLAGS = -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF

# ===============================
# Default target
# ===============================

all: deps seal project

# ===============================
# Dependencias
# ===============================

deps:
	@echo "Checking dependencies..."
	sudo apt update
	sudo apt install -y build-essential gcc g++ make \
	libtirpc-dev cmake libboost-all-dev \
	libprotobuf-dev protobuf-compiler python3 \
	gcc-9 g++-9 clang
	@echo "Dependencies installed."

# ===============================
# Clonar y compilar SEAL
# ===============================

seal:
	@if [ ! -d "$(SEAL_DIR)" ]; then \
		echo "Cloning SEAL $(SEAL_VERSION)..."; \
		sudo git clone --branch $(SEAL_VERSION) https://github.com/microsoft/SEAL.git; \
	fi
	@echo "Building SEAL..."
	mkdir -p $(SEAL_BUILD)
	cd $(SEAL_BUILD) && \
	sudo CC=$(CC) CXX=$(CXX) cmake $(CMAKE_FLAGS) .. && \
	make -j
	cd $(SEAL_BUILD) && sudo make install
	@echo "SEAL built and installed."

# ===============================
# Compilar proyecto CMake
# ===============================

project:
	@echo "Building project..."
	sudo CC=$(CC) CXX=$(CXX) cmake -S . -B build
	cmake --build build -j
	@echo "Project built."

# ===============================
# Ejecutar servidor
# ===============================

run:
	./build/server

# ===============================
# Limpieza
# ===============================

clean:
	rm -rf build
	rm -rf $(SEAL_BUILD)
	@echo "Build artefacts removed."