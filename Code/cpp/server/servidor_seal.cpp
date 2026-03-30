/**
 * cpp/server/servidor_seal.cpp  —  Servidor SEAL (WSL)
 * ======================================================
 * Recibe dos ciphertexts CKKS cifrados desde Python,
 * aplica la operación indicada de forma COMPLETAMENTE cifrada
 * y devuelve el resultado.
 *
 * Protocolo (little-endian uint64_t + bytes):
 *   1. Recibe  uint64_t + bytes  → comando ("media" o "suma")
 *   2. Recibe  uint64_t + bytes  → ciphertext 1
 *   3. Recibe  uint64_t + bytes  → ciphertext 2
 *   4. Envía   uint64_t + bytes  → resultado cifrado
 *
 * Compilar (desde cpp/seal/):
 *   cmake -S . -B build && cmake --build build -j
 *   Ejecutable: build/servidor_seal
 *
 * Ejecutar desde WSL:
 *   ./build/servidor_seal
 */

#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <seal/seal.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;
using namespace seal;

#define PORT 8080

// ──────────────────────────────────────────────
//  Contexto SEAL  (parámetros idénticos al cliente Python)
// ──────────────────────────────────────────────
SEALContext crear_contexto()
{
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(
        CoeffModulus::Create(8192, {60, 40, 40, 60}));
    return SEALContext(parms);
}

// ──────────────────────────────────────────────
//  Helpers de red
// ──────────────────────────────────────────────
static void recv_todo(int sock, void *buf, size_t n)
{
    size_t recibido = 0;
    char  *ptr      = reinterpret_cast<char *>(buf);
    while (recibido < n) {
        ssize_t r = recv(sock, ptr + recibido, n - recibido, 0);
        if (r <= 0) throw runtime_error("Conexión cerrada por el cliente");
        recibido += r;
    }
}

string recv_string(int sock)
{
    uint64_t size;
    recv_todo(sock, &size, sizeof(size));
    string s(size, '\0');
    recv_todo(sock, &s[0], size);
    return s;
}

Ciphertext recv_cipher(int sock, const SEALContext &context)
{
    uint64_t size;
    recv_todo(sock, &size, sizeof(size));

    vector<char> buf(size);
    recv_todo(sock, buf.data(), size);

    stringstream ss;
    ss.write(buf.data(), size);

    Ciphertext ct;
    ct.load(context, ss);
    return ct;
}

void send_cipher(int sock, Ciphertext &ct)
{
    stringstream ss;
    ct.save(ss);
    string data = ss.str();

    uint64_t size = static_cast<uint64_t>(data.size());
    send(sock, &size, sizeof(size), 0);
    send(sock, data.data(), size,   0);
}

// ══════════════════════════════════════════════
//  Main
// ══════════════════════════════════════════════
int main()
{
    SEALContext context  = crear_contexto();
    Evaluator   evaluator(context);
    CKKSEncoder encoder (context);
    double      scale    = pow(2.0, 40);

    // ── Socket ──
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind  (server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    listen(server_fd, 1);

    cout << "[servidor_seal] Esperando en puerto " << PORT << "..." << endl;

    socklen_t addrlen = sizeof(addr);

    while (true)
    {
        int client = accept(server_fd,
                            reinterpret_cast<sockaddr *>(&addr),
                            &addrlen);
        cout << "[servidor_seal] Cliente conectado" << endl;

        try {
            // 1. Recibir comando
            string cmd = recv_string(client);
            cout << "[servidor_seal] Comando: \"" << cmd << "\"" << endl;

            // 2. Recibir ciphertexts (el servidor nunca ve los datos en claro)
            cout << "[servidor_seal] Recibiendo ct1..." << endl;
            Ciphertext ct1 = recv_cipher(client, context);

            cout << "[servidor_seal] Recibiendo ct2..." << endl;
            Ciphertext ct2 = recv_cipher(client, context);

            // 3. Operación homomórfica
            Ciphertext resultado;
            evaluator.add(ct1, ct2, resultado);

            if (cmd == "media") {
                Plaintext plain_half;
                encoder.encode(0.5, scale, plain_half);
                evaluator.multiply_plain_inplace(resultado, plain_half);
                evaluator.rescale_to_next_inplace(resultado);
                cout << "[servidor_seal] Aplicado: (ct1 + ct2) * 0.5" << endl;
            } else {
                cout << "[servidor_seal] Aplicado: ct1 + ct2" << endl;
            }

            // 4. Enviar resultado cifrado
            send_cipher(client, resultado);
            cout << "[servidor_seal] Resultado enviado" << endl;

        } catch (const exception &e) {
            cerr << "[servidor_seal] Error con cliente: " << e.what() << endl;
        }

        close(client);
        cout << "[servidor_seal] Esperando nueva conexión..." << endl;
    }

    close(server_fd);
    return 0;
}