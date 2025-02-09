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

vector<string> get_files_in_folder(const std::string &folder_address)    {
    vector<string> result;
    for (const auto & entry : std::filesystem::directory_iterator(folder_address)) {
        // skip directories:
        if (std::filesystem::is_directory(entry.path().string()))   {
            continue;
        }

        result.push_back(entry.path().string());
    }
    sort(result.begin(), result.end());
    return result;
};

string get_filename_from_address(const string &address) {
    const size_t last_slash = address.find_last_of("/\\");
    return address.substr(last_slash + 1);
}


int main(int argc, const char **argv)   {
    if (argc != 4)  {
        cout << "3 input arguments are expected:\n";
        cout << "1st = file with RSA keys\n";
        cout << "2nd = folder with files to encrypt\n";
        cout << "3rd = folder with encrypted files\n";
        return 1;
    }

    try {
        const string key_file       = argv[1];
        const string input_folder   = argv[2];
        const string output_folder  = argv[3];

        vector<string> files_to_encrypt = get_files_in_folder(input_folder);
        vector<string> already_present_encrypted_files = get_files_in_folder(output_folder);
        for (string &file : already_present_encrypted_files) {
            file = get_filename_from_address(file);
        }

        vector<string> newly_added_files;
        for (const string &input_file : files_to_encrypt)   {
            const string filename = get_filename_from_address(input_file);
            if (std::find(already_present_encrypted_files.begin(), already_present_encrypted_files.end(), filename) != already_present_encrypted_files.end())   {
                continue;
            }

            // append a timestamp to the binary name
            const string output_address = output_folder + "/" + filename;

            // encrypt the files
            BinaryEncryptor binary_encryptor(key_file, vector<string>({input_file}));
            binary_encryptor.create_encrypted_binary(output_address);

            cout << "Encrypting file:\t" << filename << endl;
        }

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}