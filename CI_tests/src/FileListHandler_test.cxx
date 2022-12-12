#include "../../CI_tests/headers/FileListHandler_test.h"

#include "../../EncryptedBackuper/FileListHandler.h"

#include "../../EncryptedBackuper/RSA_related_math_functions.h"
#include "../../EncryptedBackuper/SHA3Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <fstream>
#include <vector>
#include <iostream>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;

void EncryptedBackuperTests::CreateHashListFile_test(int argc, const char **argv)    {
    if (argc != 5)  {
        throw std::string("Three input arguments are required! Filelist address, output hash file and correct hash of the hash file");
    }

    const std::string &filelist_address      = argv[2];
    const std::string &output_hash_file      = argv[3];
    const std::string &hash_of_hash_file     = argv[4];

    FileListHandler filelist_handler;
    filelist_handler.load_filelist_from_file(filelist_address);
    filelist_handler.evaluate_file_sizes_from_disk();
    vector<string>          file_names = filelist_handler.get_list_of_files_names_only();
    vector<long long int>   file_sizes = filelist_handler.get_files_sizes();

    for (unsigned int i = 0; i < file_names.size(); i++)  {
        cout << file_names[i] << "\t\t" << file_sizes[i] << endl;
    }

    filelist_handler.create_files_hashes_file(output_hash_file);

    const cpp_int hash_correct = cpp_int(hash_of_hash_file);
    const cpp_int hash_calculated = calculate_sha3_from_file(output_hash_file, 256);

    if (hash_calculated != hash_correct)  {
        throw string("Hashes do not match!");
    }
};
