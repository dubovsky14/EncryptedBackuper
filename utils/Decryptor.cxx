#include "../EncryptedBackuper/BinaryDecryptor.h"

#include <iostream>
#include <vector>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>


using namespace boost::multiprecision;

using namespace std;
using namespace EncryptedBackuper;

int main(int argc, const char **argv)   {
    if (argc != 3)  {
        cout << "2 input arguments are expected:\n";
        cout << "1st = Encrypted file\n";
        cout << "2nd = folder where decrypted files should be saved\n";
        return 1;
    }


    try {
        const string encrypted_file = argv[1];
        const string output_folder = argv[2];

        cout << "Please type in your password and hit enter\n";
        string password;
        cin >> password;


        BinaryDecryptor binary_encryptor(encrypted_file);
        binary_encryptor.decrypt_files(output_folder, password);

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}