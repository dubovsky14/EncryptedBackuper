#include "../../CI_tests/headers/KeyFileHandler_test.h"

#include "../../EncryptedBackuper/KeyFileHandler.h"
#include "../../EncryptedBackuper/RSA_related_math_functions.h"

#include <iostream>
#include <string>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;


void EncryptedBackuperTests::KeyFileHandler_test(unsigned int rsa_type) {
    const string password = "1234567";
    const string key_file = "keys_test.txt";

    CreateKeyFile(key_file, password, rsa_type);
    ValidateKeyFile(key_file, password, rsa_type);
};

void EncryptedBackuperTests::CreateKeyFile(const std::string &key_file, const std::string &password, unsigned int rsa_key_lenght)   {
    KeyFileHandler  key_file_handler;
    key_file_handler.generate_keys(rsa_key_lenght);
    key_file_handler.save_keys_to_file(key_file, password);
};

void EncryptedBackuperTests::ValidateKeyFile(const std::string &key_file, const std::string &password, unsigned int rsa_key_lenght) {
    KeyFileHandler  key_file_handler;
    key_file_handler.load_keys_from_file(key_file, password);

    cout << "RSA-type: " << key_file_handler.get_rsa_type() << endl;
    cout << "pq = 0x" << std::hex << key_file_handler.get_pq() << endl;
    cout << "public_key = 0x" << std::hex << key_file_handler.get_public_key() << endl;
    cout << "private_key = 0x" << std::hex << key_file_handler.get_private_key() << endl;

    cpp_int message = 4859;
    cpp_int signature = square_and_multiply(message, key_file_handler.get_private_key(), key_file_handler.get_pq());
    cpp_int signature_decr = square_and_multiply(signature, key_file_handler.get_public_key(), key_file_handler.get_pq());

    cout << "message: " << message << endl;
    cout << "signature: " << signature << endl;
    cout << "signature_decr: " << signature_decr << endl;

    if (message != signature_decr)  {
        throw std::string("Message and decrypted signature do not match!");
    }
};

