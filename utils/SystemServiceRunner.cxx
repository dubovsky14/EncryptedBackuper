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

// Create encrypted back-up. Return the address of the file if it was created, return empty string if files have not been changed wrt. previous back-up
string Encrypt(const string &key_file, const string &filelist, const string &output_without_suffix, const string &hash_file) {
    FileListHandler filelist_handler;
    filelist_handler.load_filelist_from_file(filelist);

    // Check if the files are up-to-date
    if (std::filesystem::exists(hash_file)) {
        if (filelist_handler.files_are_up_to_date(hash_file))   {
            return "";
        };
    }

    // append a timestamp to the binary name
    const string output_address = output_without_suffix + "_" + std::to_string(time(0));

    // encrypt the files
    BinaryEncryptor binary_encryptor(key_file, filelist);
    binary_encryptor.create_encrypted_binary(output_address);

    // update hash file
    filelist_handler.create_files_hashes_file(hash_file);

    return output_address;
}

void CopyToRemote(const string &encrypted_file_address, const string &remote_address)   {
    // copy the encrypted file to the remote address
    const string command = "scp " + encrypted_file_address + " " + remote_address;
    const int system_return = system(command.c_str());

    if (system_return != 0) {
        throw "Error in copying the encrypted file to the remote address";
    }
}

int main(int argc, const char **argv)   {
    if (argc != 6)  {
        cout << "4 input arguments are expected:\n";
        cout << "1st = file with RSA keys\n";
        cout << "2nd = filelist\n";
        cout << "3rd = address and name of the binary (timestamp will be appended to it)\n";
        cout << "4th = address of the hash file\n";
        cout << "5th = address of the remote server\n";
        return 1;
    }

    try {
        const string key_file = argv[1];
        const string filelist = argv[2];
        const string output_without_suffix = argv[3];
        const string hash_file = argv[4];
        const string remote_address = argv[5];

        const string output_address = Encrypt(key_file, filelist, output_without_suffix, hash_file);
        if (output_address == "") {
            return 0;
        }

        CopyToRemote(output_address, remote_address);

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}