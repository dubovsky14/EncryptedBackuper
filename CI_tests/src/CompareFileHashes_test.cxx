#include "../../CI_tests/headers/CompareFileHashes_test.h"

#include "../../EncryptedBackuper/SHA3Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

void EncryptedBackuperTests::CompareFileHashes_test(int argc, const char **argv)    {
    if (argc != 4)  {
        throw std::string("CompareFileHashes_test::Three input arguments are required! Type of test, file1 and file2");
    }

    const std::string &file1      = argv[2];
    const std::string &file2      = argv[3];

    const cpp_int hash_file1 = calculate_sha3_from_file(file1, 256);
    const cpp_int hash_file2 = calculate_sha3_from_file(file2, 256);

    if (hash_file1 != hash_file2)   {
        throw std::string("Files are different: \"" + file1 + "\" and \"" + file2 + "\"");
    }
};

