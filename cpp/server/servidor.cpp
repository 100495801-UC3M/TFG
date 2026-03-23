#include <iostream>
#include <vector>
#include <sstream>
#include <seal/seal.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

using namespace std;
using namespace seal;

const string SEAL_PATH = "./Seal";

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096

SEALContext create_context()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, {60,40,40,60}));

    return SEALContext(parms);
}

Ciphertext recv_cipher(int sock, SEALContext &context)
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

void send_cipher(int sock, Ciphertext &ct)
{
    stringstream ss;
    ct.save(ss);

    string data = ss.str();

    uint64_t size = data.size();

    send(sock, &size, sizeof(size), 0);
    send(sock, data.data(), size, 0);
}

void *handle_client(void *arg)
{
    int fd = *(int*)arg;
    free(arg);

    SEALContext context = create_context();
    Evaluator evaluator(context);

    cout << "Receiving ciphertexts..." << endl;

    Ciphertext c1 = recv_cipher(fd, context);
    Ciphertext c2 = recv_cipher(fd, context);

    Ciphertext result;

    evaluator.add(c1, c2, result);

    cout << "Sum computed" << endl;

    send_cipher(fd, result);

    close(fd);

    return NULL;
}

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd,(sockaddr*)&addr,sizeof(addr));

    listen(server_fd,10);

    cout << "Server running on port 8080" << endl;

    while(true)
    {
        int *client = (int*)malloc(sizeof(int));

        *client = accept(server_fd,NULL,NULL);

        pthread_t tid;

        pthread_create(&tid,NULL,handle_client,client);

        pthread_detach(tid);
    }
}