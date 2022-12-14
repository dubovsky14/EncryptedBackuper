#include "../../CI_tests/headers/KeyEncryptionTool_test.h"

#include "../../EncryptedBackuper/RSA_related_math_functions.h"
#include "../../EncryptedBackuper/RandomNumberGenerator.h"
#include "../../EncryptedBackuper/KeyEncryptionTool.h"
#include "../../EncryptedBackuper/StringOperations.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <iostream>
#include <string>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;

void EncryptedBackuperTests::KeyEncryptionTool_test(unsigned int key_length)  {
    boost::multiprecision::cpp_int pq, private_key, public_key(65537);
    const string password = "testing password";

    bool valid_key = false;
    unsigned int key_attempt = 0;
    while (!valid_key && key_attempt < 100) {
        valid_key = generate_rsa_keys(&pq, &private_key, public_key, key_length);
        key_attempt++;
    }

    if (!valid_key) {
        throw std::string("Unable to generate RSA pair of keys!");
    }

    const cpp_int private_key_encrypted = KeyEncryptionTool::encrypt_private_key(private_key, password, key_length);

    KeyEncryptionTool key_encryption_tool_1;
    key_encryption_tool_1.set_rsa_keys(pq, public_key, private_key_encrypted, key_length);

    RandomNumberGenerator rng256(256);
    const cpp_int random_aes_key = rng256.Random();

    const string key_summary_string = key_encryption_tool_1.produce_key_summary_string(random_aes_key);


    KeyEncryptionTool key_encryption_tool_2;
    key_encryption_tool_1.set_rsa_keys(pq, public_key, private_key_encrypted, key_length);
    key_encryption_tool_2.load_key_summary_string(key_summary_string, password);

    cout << "Private key original:  "  << convert_cpp_int_to_hex_string(private_key) << endl;
    cout << "Private key encrypted: "  << convert_cpp_int_to_hex_string(private_key_encrypted) << endl;
    cout << "Private key recovered: "  << convert_cpp_int_to_hex_string(key_encryption_tool_2.get_rsa_private_key()) << endl;
    cout << endl;

    cout << "AES key original: "  << convert_cpp_int_to_hex_string(random_aes_key) << endl;
    cout << "AES key encrypted: " << SplitString((SplitString(key_summary_string, ";")[4]), "=")[1] << endl;
    cout << "AES key recovered: " << convert_cpp_int_to_hex_string(key_encryption_tool_2.get_aes_key()) << endl;
    cout << endl;

    if (private_key != key_encryption_tool_2.get_rsa_private_key()) {
        throw std::string("Original RSA private key and the private key after decryption do not match!");
    }

    if (random_aes_key != key_encryption_tool_2.get_aes_key()) {
        throw std::string("Original AES key and the AES key after decryption do not match!");
    }
};