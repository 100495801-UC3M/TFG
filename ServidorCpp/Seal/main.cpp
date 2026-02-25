#include <iostream>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    // Claves
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Valor de ejemplo
    double input = 5.0;

    Plaintext plain;
    encoder.encode(input, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // Servidor multiplica por 2
    Plaintext plain_two;
    encoder.encode(2.0, scale, plain_two);

    evaluator.multiply_plain_inplace(encrypted, plain_two);
    evaluator.rescale_to_next_inplace(encrypted);

    // Cliente descifra
    Plaintext result_plain;
    decryptor.decrypt(encrypted, result_plain);

    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "Resultado: " << result[0] << endl;

    return 0;
}