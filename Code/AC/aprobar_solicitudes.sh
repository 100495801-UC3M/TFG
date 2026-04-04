#!/bin/bash

# Directorios
DIR="."
SOLICITUDES_DIR="$DIR/solicitudes"
CERTS_DIR="$DIR/nuevoscerts"

# Variables de control
TOTAL_SOLICITUDES=0
APROBADAS=0
RECHAZADAS_USUARIO=0
RECHAZADAS_ERROR=0

# Función para procesar un certificado
procesar_certificado() {
    local CSR_FILE="$1"
    local PASS_PHRASE="$2"
    local AUTO_APPROVE="$3"
    
    if [ ! -f "$CSR_FILE" ]; then
        return 1
    fi
    
    # Extraer el nombre del usuario del archivo
    USERNAME=$(basename "$CSR_FILE" .pem)
    CSR_PATH="$CSR_FILE"
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Certificado: $USERNAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Si no es aprobación automática, preguntar al usuario
    if [ "$AUTO_APPROVE" != "1" ]; then
        read -p "¿Quieres firmar este certificado? (Enter=sí, n/no=rechazar): " RESPONSE
        if [[ "$RESPONSE" == "n" || "$RESPONSE" == "no" ]]; then
            echo "❌ Certificado rechazado por el usuario"
            ((RECHAZADAS_USUARIO++))
            return 0
        fi
    fi

    # Obtener el índice del certificado en index.txt
    INDEX=$(grep -w "CN=$USERNAME" "$DIR/index.txt" | awk '{if ($1 == "V") print $3}' | tr -d '\r')

    if [ -n "$INDEX" ]; then
        # Si se encuentra el índice en el archivo, revocar el certificado
        CERT_PATH="$CERTS_DIR/$INDEX.pem"
        echo "🔄 El certificado de '$USERNAME' ya existe. Revocando el certificado anterior..."
        
        # Revocar el certificado anterior antes de aprobar el nuevo
        openssl ca -revoke $CERT_PATH -config openssl.cnf -passin pass:"$PASS_PHRASE" -batch >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "❌ Error al revocar el certificado anterior."
            ((RECHAZADAS_ERROR++))
            return 0
        fi
        echo "✅ Certificado anterior revocado: $CERT_PATH"
    fi

    # Leer el contenido de serial para obtener el número que toca
    if [ ! -f "$DIR/serial" ]; then
        echo "❌ El archivo serial no existe."
        ((RECHAZADAS_ERROR++))
        return 0
    fi
    
    SERIAL=$(cat "$DIR/serial" | tr -d '\r\n')

    # Aprobar la solicitud
    echo "🔄 Firmando el certificado..."
    openssl ca -in "$CSR_PATH" -days 365 -config openssl.cnf -batch -passin pass:"$PASS_PHRASE" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "❌ Error al firmar la solicitud."
        ((RECHAZADAS_ERROR++))
        return 0
    fi

    ALGORITHM=$(openssl req -in "$CSR_PATH" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk -F": " '{print $2}')
    echo "✅ Certificado firmado exitosamente. Algoritmo: $ALGORITHM"

    # Actualizar la base de datos del usuario
    DB_DIR="../app/users.py"

    if [ ! -f "$DB_DIR" ]; then
        echo "❌ El archivo $DB_DIR no existe."
        ((RECHAZADAS_ERROR++))
        return 0
    fi

    echo "🔄 Actualizando la base de datos..."
    python3 "$DB_DIR" "$USERNAME" "$SERIAL" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "⚠️ Error al actualizar la base de datos para $USERNAME"
        ((RECHAZADAS_ERROR++))
        return 0
    fi
    echo "✅ Base de datos actualizada."

    # Eliminar la solicitud procesada
    rm "$CSR_PATH"
    echo "🗑️ Certificado $CSR_PATH eliminado."
    echo "✅ Certificado de $USERNAME aprobado correctamente."
    ((APROBADAS++))
    return 0
}

# ============ INICIO DEL SCRIPT ============

# Contar solicitudes disponibles
SOLICITUDES_COUNT=$(ls -1 "$SOLICITUDES_DIR"/*.pem 2>/dev/null | wc -l)

if [ "$SOLICITUDES_COUNT" -eq 0 ]; then
    echo "❌ No hay solicitudes para procesar en $SOLICITUDES_DIR"
    exit 1
fi

echo "🔐 Se encontraron $SOLICITUDES_COUNT solicitud(es) pendiente(s)"
echo ""

# Pedir la contraseña de la CA
read -sp "Introduce la contraseña de la CA (./privado/ca1key.pem): " PASS_PHRASE
echo ""
echo ""

# Preguntar modo de procesamiento
echo "¿Cómo deseas proceder?"
echo "1) Firmar TODOS los certificados automáticamente"
echo "2) Preguntar para cada certificado"
read -p "Elige opción (1 o 2): " OPCION

if [ "$OPCION" == "1" ]; then
    AUTO_APPROVE=1
    echo "✅ Modo: Aprobación automática de todos los certificados"
else
    AUTO_APPROVE=0
    echo "✅ Modo: Preguntar para cada certificado"
fi

echo ""

# Procesar todas las solicitudes
for CSR_FILE in "$SOLICITUDES_DIR"/*.pem; do
    procesar_certificado "$CSR_FILE" "$PASS_PHRASE" "$AUTO_APPROVE"
done


# Limpiar archivos innecesarios (una sola vez al final)
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

# Mostrar resumen final
echo ""
echo "╔════════════════════════════════════════╗"
echo "║         RESUMEN DEL PROCESAMIENTO      ║"
echo "╠════════════════════════════════════════╣"
echo "║ Total de solicitudes: $SOLICITUDES_COUNT"
echo "║ ✅ Aprobadas: $APROBADAS"
echo "║ ❌ Rechazadas por usuario: $RECHAZADAS_USUARIO"
echo "║ ⚠️  Errores de procesamiento: $RECHAZADAS_ERROR"
echo "╚════════════════════════════════════════╝"
echo ""
echo "🎉 Procesamiento completado."

