#include "../../CI_tests/headers/RSA_test.h"
#include "../../CI_tests/headers/SHA3_512_test.h"

#include <iostream>
#include <string>

using namespace std;
using namespace EncryptedBackuperTests;

int main(int argc, const char **argv)   {

    try {
        if (argc != 2)  {
            throw std::string("Invalid input! One input argument is required: Type of the test");
        }
        const string test_type = argv[1];

        if (test_type == "RSA-512")  RSA_test(512);
        if (test_type == "SHA3-512") SHA3_512_test();
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