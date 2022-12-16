#include "../EncryptedBackuper/BinaryEncryptor.h"

#include "../EncryptedBackuper/FileListHandler.h"

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <ctime>

#include <boost/multiprecision/cpp_int.hpp>


using namespace boost::multiprecision;

using namespace std;
using namespace EncryptedBackuper;

int main(int argc, const char **argv)   {
    if (argc != 5)  {
        cout << "4 input arguments are expected:\n";
        cout << "1st = file with RSA keys\n";
        cout << "2nd = filelist\n";
        cout << "3rd = address and name of the binary (timestamp will be appended to it)\n";
        cout << "4th = address of the hash file\n";
        return 1;
    }

    try {
        const string key_file = argv[1];
        const string filelist = argv[2];
        const string output_without_suffix = argv[3];
        const string hash_file = argv[4];

        FileListHandler filelist_handler;
        filelist_handler.load_filelist_from_file(filelist);

        // Check if the files are up-to-date
        if (std::filesystem::exists(hash_file)) {
            if (filelist_handler.files_are_up_to_date(hash_file))   {
                // files are up-to-date, so I have nothing to do here
                return 0;
            };
        }

        // append a timestamp to the binary name
        const string output_address = output_without_suffix + "_" + std::to_string(time(0));

        // encrypt the files
        BinaryEncryptor binary_encryptor(key_file, filelist);
        binary_encryptor.create_encrypted_binary(output_address);

        // update hash file
        filelist_handler.create_files_hashes_file(hash_file);

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}