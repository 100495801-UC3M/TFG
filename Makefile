# =========================================
# CONFIGURACIÓN GLOBAL
# =========================================

CPP_SERVER_DIR = ServidorCpp
CPP_SEAL_DIR = $(CPP_SERVER_DIR)/Seal
RPC_DIR = $(CPP_SERVER_DIR)

SEAL_VERSION = v3.6.6
SEAL_REPO = https://github.com/microsoft/SEAL.git
SEAL_DIR = $(CPP_SEAL_DIR)/SEAL
SEAL_BUILD = $(SEAL_DIR)/build



CC = gcc-9
CXX = g++-9
CMAKE_FLAGS = -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF

# =========================================
# TARGET POR DEFECTO
# =========================================

all: deps seal project rpc

# =========================================
# DEPENDENCIAS
# =========================================

deps:
	@echo "Checking dependencies..."
	sudo apt update
	sudo apt install -y build-essential gcc g++ make \
	libtirpc-dev cmake libboost-all-dev \
	libprotobuf-dev protobuf-compiler python3 \
	gcc-9 g++-9 clang
	@echo "Dependencies OK."

# =========================================
# SEAL
# =========================================

seal:
	@if [ ! -f "$(SEAL_DIR)/CMakeLists.txt" ]; then \
		echo "Cloning SEAL $(SEAL_VERSION) into $(SEAL_DIR)..."; \
		rm -rf "$(SEAL_DIR)"; \
		sudo git clone --branch $(SEAL_VERSION) $(SEAL_REPO) "$(SEAL_DIR)"; \
	else \
		echo "SEAL already properly cloned. Skipping clone."; \
	fi

	@if [ ! -f "$(SEAL_BUILD)/Makefile" ]; then \
		echo "Building SEAL..."; \
		mkdir -p "$(SEAL_BUILD)"; \
		cd "$(SEAL_BUILD)" && \
		sudo CC=$(CC) CXX=$(CXX) cmake $(CMAKE_FLAGS) .. && \
		make -j; \
	else \
		echo "SEAL already built. Skipping build."; \
	fi

# =========================================
# PROYECTO CMAKE (Seal/)
# =========================================

project:
	@echo "Building CMake project in Seal..."
	sudo CC=$(CC) CXX=$(CXX) cmake -S "$(CPP_SEAL_DIR)" -B "$(CPP_SEAL_DIR)/build"
	cmake --build "$(CPP_SEAL_DIR)/build" -j
	@echo "Seal project built."

# =========================================
# RPC SERVER
# =========================================

rpc:
	@echo "Building RPC server..."
	$(MAKE) -C "$(RPC_DIR)"
	@echo "RPC server built."

# =========================================
# RUN HELPERS
# =========================================

run-server:
	./$(CPP_SERVER_DIR)/servidor -p 8080

run-logger:
	python3 ./$(CPP_SERVER_DIR)/test.py -s localhost -p 8080

run-seal:
	./$(CPP_SEAL_DIR)/build/server

# =========================================
# CLEAN
# =========================================

clean:
	rm -rf $(SEAL_BUILD)
	rm -rf "$(CPP_SEAL_DIR)/build"
	$(MAKE) -C "$(RPC_DIR)" clean
	@echo "All build artefacts removed."