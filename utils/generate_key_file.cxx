#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"
#include "../EncryptedBackuper/KeyFileHandler.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <iostream>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

int main(int argc, const char **argv)   {
    if (argc != 3)  {
        cout << "Two input arguments are expected:";
        cout << "\t1st = length of RSA key:";
        cout << "\t2nd = address of the file with generated keys";
    }

    //const unsigned int rsa_type = std::stoi(std::string(argv[1]));
    const string       key_file = argv[2];


    cout << "Please type in your password and hit enter\n";
    string password;
    cin >> password;

    KeyFileHandler  key_file_handler;
    key_file_handler.load_keys_from_file(key_file, password);
    password = "";

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
    return 0;



/*
    if (argc != 3)  {
        cout << "Two input arguments are expected:";
        cout << "\t1st = length of RSA key:";
        cout << "\t2nd = address of the file with generated keys";
    }

    const unsigned int rsa_type = std::stoi(std::string(argv[1]));
    const string       key_file = argv[2];

    KeyFileHandler  key_file_handler;
    key_file_handler.generate_keys(rsa_type);

    cout << "Please type in your password and hit enter\n";
    string password;
    cin >> password;

    key_file_handler.save_keys_to_file(key_file, password);
    password = "";
*/

    return 0;
};