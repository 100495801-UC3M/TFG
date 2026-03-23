#include <iostream>
#include <vector>
#include <seal/seal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
using namespace seal;

Ciphertext receive_ciphertext(int sock, SEALContext &context)
{
    uint64_t size;
    recv(sock, &size, sizeof(size), MSG_WAITALL);

    vector<char> buffer(size);
    recv(sock, buffer.data(), size, MSG_WAITALL);

    stringstream ss;
    ss.write(buffer.data(), size);

    Ciphertext ct;
    ct.load(context, ss);

    return ct;
}

void send_ciphertext(int sock, Ciphertext &ct)
{
    stringstream ss;
    ct.save(ss);
    string data = ss.str();

    uint64_t size = data.size();

    send(sock, &size, sizeof(size), 0);
    send(sock, data.data(), size, 0);
}

int main()
{
    // ===============================
    // SEAL setup
    // ===============================

    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // ===============================
    // Crear servidor
    // ===============================

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    bind(server_fd, (sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    cout << "Servidor esperando conexion..." << endl;

    socklen_t addrlen = sizeof(address);

    int client_socket =
        accept(server_fd, (sockaddr *)&address, &addrlen);

    cout << "Cliente conectado" << endl;

    // ===============================
    // Recibir datos
    // ===============================

    Ciphertext encrypted_mean =
        receive_ciphertext(client_socket, context);

    Ciphertext encrypted_new =
        receive_ciphertext(client_socket, context);

    double count;
    recv(client_socket, &count, sizeof(double), MSG_WAITALL);

    cout << "Count recibido: " << count << endl;

    // ===============================
    // mean * count
    // ===============================

    Plaintext plain_count;
    encoder.encode(count, scale, plain_count);

    Ciphertext mean_scaled;

    evaluator.multiply_plain(
        encrypted_mean,
        plain_count,
        mean_scaled);

    evaluator.rescale_to_next_inplace(mean_scaled);

    // ===============================
    // Alinear escala del nuevo vector
    // ===============================

    Ciphertext new_aligned = encrypted_new;
    new_aligned.scale() = mean_scaled.scale();

    // ===============================
    // sum = mean_scaled + new
    // ===============================

    Ciphertext sum;

    evaluator.add(
        mean_scaled,
        new_aligned,
        sum);

    // ===============================
    // multiplicar por 1/(count+1)
    // ===============================

    double inv = 1.0 / (count + 1);

    Plaintext plain_inv;
    encoder.encode(inv, scale, plain_inv);

    Ciphertext result;

    evaluator.multiply_plain(
        sum,
        plain_inv,
        result);

    evaluator.rescale_to_next_inplace(result);

    // ===============================
    // enviar resultado
    // ===============================

    send_ciphertext(client_socket, result);

    cout << "Resultado enviado al cliente" << endl;

    close(client_socket);
    close(server_fd);
}