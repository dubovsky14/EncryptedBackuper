#include "../EncryptedBackuper/BinaryDecryptor.h"

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

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

int main(int argc, const char **argv)   {
    if (argc != 3)  {
        cout << "2 input arguments are expected:\n";
        cout << "1st = Encrypted file\n";
        cout << "2nd = folder where decrypted files should be saved\n";
        return 1;
    }


    try {
        const string encrypted_input = argv[1];
        const string output_folder = argv[2];

        cout << "Please type in your password and hit enter\n";
        string password;
        cin >> password;

        if (std::filesystem::is_directory(encrypted_input))   {
            const vector<string> files = get_files_in_folder(encrypted_input);
            for (const string &file : files)    {
                cout << "Decrypting file: " << file << endl;
                BinaryDecryptor binary_encryptor(file);
                binary_encryptor.decrypt_files(output_folder, password);
            }
            return 0;
        }

        BinaryDecryptor binary_encryptor(encrypted_input);
        binary_encryptor.decrypt_files(output_folder, password);

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}