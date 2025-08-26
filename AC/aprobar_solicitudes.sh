#!/bin/bash

# Directorios
DIR="."
SOLICITUDES_DIR="$DIR/solicitudes"
CERTS_DIR="$DIR/nuevoscerts"

# Pedir el nombre del usuario
read -p "Introduce el nombre del usuario: " USERNAME

# Comprobar si la solicitud existe
CSR_PATH="$SOLICITUDES_DIR/$USERNAME.pem"
if [ ! -f "$CSR_PATH" ]; then
    echo "❌ La solicitud '$CSR_PATH' no existe."
    exit 1
fi


# Obtener el índice del certificado en index.txt
INDEX=$(grep -w "CN=$USERNAME" "$DIR/index.txt" | awk '{if ($1 == "V") print $3}')

if [ -n "$INDEX" ]; then
    # Si se encuentra el índice en el archivo, revocar el certificado
    CERT_PATH="$CERTS_DIR/$INDEX.pem"
    echo "🔄 El certificado de '$USERNAME' ya existe. Revocando el certificado anterior..."
    
    # Revocar el certificado anterior antes de aprobar el nuevo
    openssl ca -revoke $CERT_PATH -config openssl.cnf
    if [ $? -ne 0 ]; then
        echo "❌ Error al revocar el certificado anterior."
        exit 1
    fi
    echo "✅ Certificado anterior revocado: $CERT_PATH"
fi


# Leer el contenido de serial para obtener el número que toca
if [ -f "$DIR/serial" ]; then
    SERIAL=$(cat "$DIR/serial")
else
    echo "El archivo serial no existe."
    exit 1
fi


# Aprobar la solicitud
echo "🔄 Aprobando la solicitud..."
openssl ca -in "$CSR_PATH" -days 365 -config openssl.cnf

# Codigo extra para pobrar la fecha la caducidad
# openssl ca -in "$CSR_PATH" -startdate "20241202100100Z" -enddate "20241207111500Z" -config openssl.cnf


if [ $? -ne 0 ]; then
    echo "❌ Error al aprobar la solicitud."
    exit 1
fi

ALGORITHM=$(openssl req -in "$CSR_PATH" -noout -text | grep "Signature Algorithm" | head -1 | awk -F": " '{print $2}')
echo "✅ Certificado generado exitosamente. Algoritmo de firma utilizado: $ALGORITHM"

# Actualizar la base de datos del usuario
DB_DIR="../app/users.py"

if [ ! -f "$DB_DIR" ]; then
    echo "El archivo $DB_DIR no existe."
    exit 1
fi

echo "🔄 Actualizando la base de datos con el nuevo número de serie: $SERIAL"
python3 "$DB_DIR" "$USERNAME" "$SERIAL"

if [ $? -ne 0 ]; then
    echo "❌ Error al actualizar la base de datos."
    exit 1
fi
echo "✅ Base de datos actualizada correctamente."


# Eliminar archivos innecesarios
if [ -f "$DIR/index.txt.old" ]; then
    rm "$DIR/index.txt.old"
    echo "🗑️ Archivo index.txt.old eliminado."
fi

if [ -f "$DIR/index.txt.attr.old" ]; then
    rm "$DIR/index.txt.attr.old"
    echo "🗑️ Archivo index.txt.attr.old eliminado."
fi

if [ -f "$DIR/serial.old" ]; then
    rm "$DIR/serial.old"
    echo "🗑️ Archivo serial.old eliminado."
fi

# Eliminar la solicitud procesada
rm $CSR_PATH
echo "🗑️ Archivo $CSR_PATH eliminado."

echo "🎉 Solicitud apobada correctamente."
