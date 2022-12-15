#include "../EncryptedBackuper/BinaryEncryptor.h"

#include <iostream>
#include <vector>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>


using namespace boost::multiprecision;

using namespace std;
using namespace EncryptedBackuper;

int main(int argc, const char **argv)   {
    if (argc != 4)  {
        cout << "3 input arguments are expected:\n";
        cout << "1st = file with RSA keys\n";
        cout << "2nd = filelist\n";
        cout << "3rd = address of the output binary\n";
        return 1;
    }

    try {
        const string key_file = argv[1];
        const string filelist = argv[2];
        const string output_address = argv[3];

        BinaryEncryptor binary_encryptor(key_file, filelist);
        binary_encryptor.create_encrypted_binary(output_address);

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}