#include "../CI_tests/headers/RSA_test.h"
#include "../CI_tests/headers/SHA3_test.h"
#include "../CI_tests/headers/KeyFileHandler_test.h"
#include "../CI_tests/headers/FileListHandler_test.h"
#include "../CI_tests/headers/KeyEncryptionTool_test.h"


#include <iostream>
#include <string>

using namespace std;
using namespace EncryptedBackuperTests;

int main(int argc, const char **argv)   {

    try {
        if (argc < 2)  {
            throw std::string("Invalid input! One input argument is required: Type of the test");
        }
        const string test_type = argv[1];

        if      (test_type == "RSA-512")                    RSA_test(512);
        else if (test_type == "RSA-1024")                   RSA_test(1024);
        else if (test_type == "RSA-2048")                   RSA_test(2048);
        else if (test_type == "SHA3-224")                   SHA3_test_sample_strings(224);
        else if (test_type == "SHA3-256")                   SHA3_test_sample_strings(256);
        else if (test_type == "SHA3-384")                   SHA3_test_sample_strings(384);
        else if (test_type == "SHA3-512")                   SHA3_test_sample_strings(512);
        else if (test_type == "SHA3-224-file")              SHA3_test_file(224, argc, argv);
        else if (test_type == "SHA3-256-file")              SHA3_test_file(256, argc, argv);
        else if (test_type == "SHA3-384-file")              SHA3_test_file(384, argc, argv);
        else if (test_type == "SHA3-512-file")              SHA3_test_file(512, argc, argv);
        else if (test_type == "FileListHandler-hash-file")  CreateHashListFile_test(argc, argv);
        else if (test_type == "FileListHandler-up-to-date") FileListHandler_up_to_date_files_test(argc, argv);
        else if (test_type == "KeyFileHandler")             KeyFileHandler_test(512);
        else if (test_type == "KeyEncryptionTool")          KeyEncryptionTool_test(1024);
        else   {
            throw string("Unkown test: \"" + test_type + "\'");
        }

        return 0;
    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
    abort();
}