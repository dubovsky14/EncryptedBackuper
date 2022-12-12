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

    const unsigned int rsa_type = std::stoi(std::string(argv[1]));
    const string       key_file = argv[2];

    KeyFileHandler  key_file_handler;
    key_file_handler.generate_keys(rsa_type);

    cout << "Please type in your password and hit enter\n";
    string password;
    cin >> password;

    key_file_handler.save_keys_to_file(key_file, password);
    password = "";

    return 0;
};