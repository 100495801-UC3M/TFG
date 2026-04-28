#!/bin/bash

# Directorios
DIR="."
CERTS_DIR="$DIR/nuevoscerts"

# Variables de control
TOTAL_CERTIFICADOS=0
REVOCADOS=0
NO_REVOCADOS=0
ERRORES=0

# Función para revocar un certificado
revocar_certificado() {
    local CERT_FILE="$1"
    local PASS_PHRASE="$2"
    
    if [ ! -f "$CERT_FILE" ]; then
        return 1
    fi
    
    # Extraer el nombre del archivo sin extensión
    CERT_NAME=$(basename "$CERT_FILE" .pem)
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Certificado: $CERT_NAME"
    echo "Archivo: $CERT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Mostrar información del certificado
    echo "📋 Información del certificado:"
    openssl x509 -in "$CERT_FILE" -noout -subject -dates 2>/dev/null | sed 's/^/   /'
    
    # Preguntar si revocar
    read -p "¿Revocar este certificado? (Enter=sí, n/no=no revocar): " RESPONSE
    if [[ "$RESPONSE" == "n" || "$RESPONSE" == "no" ]]; then
        echo "⏭️  Certificado no revocado"
        ((NO_REVOCADOS++))
        return 0
    fi
    
    # Revocar el certificado
    echo "🔄 Revocando el certificado..."
    openssl ca -revoke "$CERT_FILE" -config openssl.cnf -passin pass:"$PASS_PHRASE" -batch >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo "❌ Error al revocar el certificado"
        ((ERRORES++))
        return 0
    fi
    
    echo "✅ Certificado revocado exitosamente"
    ((REVOCADOS++))
    return 0
}

# INICIO DEL SCRIPT

# Contar certificados disponibles
CERTIFICADOS_COUNT=$(ls -1 "$CERTS_DIR"/*.pem 2>/dev/null | wc -l)

if [ "$CERTIFICADOS_COUNT" -eq 0 ]; then
    echo "❌ No hay certificados para revocar en $CERTS_DIR"
    exit 1
fi

echo "🔐 Se encontraron $CERTIFICADOS_COUNT certificado(s) emitido(s)"
echo ""

# Pedir la contraseña de la CA
read -sp "Introduce la contraseña de la CA (./privado/ca1key.pem): " PASS_PHRASE
echo ""
echo ""

# Preguntar modo de procesamiento
echo "¿Cómo deseas proceder?"
echo "1) Preguntar para cada certificado"
echo "2) Ver lista y seleccionar cuáles revocar"
read -p "Elige opción (1 o 2): " OPCION

if [ "$OPCION" == "2" ]; then
    # Modo 2: Mostrar lista y seleccionar
    echo ""
    echo "📋 LISTA DE CERTIFICADOS:"
    echo ""
    
    declare -a CERTS_ARRAY
    INDEX=1
    for CERT_FILE in "$CERTS_DIR"/*.pem; do
        CERT_NAME=$(basename "$CERT_FILE" .pem)
        CERTS_ARRAY[$INDEX]="$CERT_FILE"
        
        # Mostrar información resumida
        SUBJECT=$(openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null | sed 's/subject=CN=//')
        echo "[$INDEX] $CERT_NAME - $SUBJECT"
        INDEX=$((INDEX + 1))
    done
    
    echo ""
    read -p "Introduce los números separados por espacios (ej: 1 3 5): " SELECTIONS
    
    for SEL in $SELECTIONS; do
        if [ -n "${CERTS_ARRAY[$SEL]}" ]; then
            revocar_certificado "${CERTS_ARRAY[$SEL]}" "$PASS_PHRASE"
        else
            echo "⚠️ Selección inválida: $SEL"
        fi
    done
else
    # Modo 1: Preguntar para cada uno
    echo "✅ Modo: Preguntar para cada certificado"
    echo ""
    
    for CERT_FILE in "$CERTS_DIR"/*.pem; do
        revocar_certificado "$CERT_FILE" "$PASS_PHRASE"
    done
fi

# Regenerar CRL (Certificate Revocation List)
echo ""
echo "🔄 Regenerando lista de revocación..."
openssl ca -gencrl -out "$DIR/crls/ca.crl" -config openssl.cnf -passin pass:"$PASS_PHRASE" >/dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Lista de revocación actualizada: $DIR/crls/ca.crl"
else
    echo "⚠️ Advertencia: No se pudo generar la lista de revocación"
fi

# Limpiar archivos innecesarios
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
echo "║         RESUMEN DE REVOCACIÓN          ║"
echo "╠════════════════════════════════════════╣"
echo "║ Total de certificados: $CERTIFICADOS_COUNT"
echo "║ ✅ Revocados: $REVOCADOS"
echo "║ ⏭️  No revocados: $NO_REVOCADOS"
echo "║ ⚠️  Errores: $ERRORES"
echo "╚════════════════════════════════════════╝"
echo ""
echo "🎉 Procesamiento completado."
