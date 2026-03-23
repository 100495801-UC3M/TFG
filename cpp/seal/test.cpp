#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    // ===============================
    // Configuración CKKS
    // ===============================

    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    // ===============================
    // Claves
    // ===============================

    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // ===============================
    // Datos de ejemplo (encuestas)
    // ===============================

    vector<double> survey1 = {400, 300};
    vector<double> survey2 = {2, 1};

    // ===============================
    // Codificar
    // ===============================

    Plaintext p1, p2;

    encoder.encode(survey1, scale, p1);
    encoder.encode(survey2, scale, p2);

    // ===============================
    // Encriptar
    // ===============================

    Ciphertext c1, c2;

    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    // ===============================
    // Simulación servidor
    // ===============================

    Ciphertext total_sum;

    evaluator.add(c1, c2, total_sum);

    // ===============================
    // Desencriptar resultado
    // ===============================

    Plaintext result_plain;

    decryptor.decrypt(total_sum, result_plain);

    vector<double> result;

    encoder.decode(result_plain, result);

    // ===============================
    // Mostrar resultado
    // ===============================

    cout << "Resultado suma total:" << endl;

    cout << result[0] << " " << result[1] << endl;

    cout << endl;

    return 0;
}