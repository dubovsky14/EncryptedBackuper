#include "../../CI_tests/headers/SHA3_512_test.h"

#include "../../EncryptedBackuper/SHA3_512_Calculator.h"

#include <iostream>
#include <string>
#include <bitset>
#include <map>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;

void EncryptedBackuperTests::SHA3_512_test()  {

    // key = string, value = correct hash, the value will be compared with the one obtained from SHA3_512_Calculator
    map<string,string>  validation_hashes;
    validation_hashes[""] = "0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";


    for (pair<string, string> string_and_hash : validation_hashes)  {
        SHA3_512_Calculator sha3_calculator;
        const string input_string = string_and_hash.first;
        const cpp_int hash_correct      = cpp_int(string_and_hash.second);
        sha3_calculator.hash_message(input_string);
        const cpp_int hash_calculated = sha3_calculator.get_hash();

        cout << "Message: " << input_string << endl;
        cout << "Calculated hash: " << std::hex << hash_calculated << endl;
        cout << "Correct hash: " << std::hex << hash_correct << endl;

        if (hash_correct != hash_calculated)    {
            throw std::string("Calculated hash does not match the correct hash defined in the test!");
        }
    }
}