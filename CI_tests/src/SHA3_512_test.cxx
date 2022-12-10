#include "../../CI_tests/headers/SHA3_512_test.h"

#include "../../EncryptedBackuper/SHA3_512_Calculator.h"
#include "../../EncryptedBackuper/RSA_related_math_functions.h"

#include <iostream>
#include <string>
#include <bitset>
#include <map>
#include <vector>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;

string cpp_to_binary_string(const cpp_int &number)   {
    vector<unsigned char> bits =  get_representation_in_base_n(number, 2);
    string result = "";
    for (unsigned char bit : bits) {
        result = to_string(bit!=0) + result;
    }
    return result;
}

void EncryptedBackuperTests::SHA3_512_test()  {

    // key = string, value = correct hash, the value will be compared with the one obtained from SHA3_512_Calculator
    map<string,string>  validation_hashes;
    validation_hashes[""] = "0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    validation_hashes["abcdef"] = "0x01309a45c57cd7faef9ee6bb95fed29e5e2e0312af12a95fffeee340e5e5948b4652d26ae4b75976a53cc1612141af6e24df36517a61f46a1a05f59cf667046a";
    validation_hashes["We shall go on to the end. We shall fight in France, we shall fight on the seas and oceans. We shall fight with growing confidence and growing strength in the air, we shall defend our island, whatever the cost may be. We shall fight on the beaches, we shall fight on the landing grounds. We shall fight in the fields, and in the streets. We shall fight in the hills. We shall never surrender!"] = "0x58e0297eca60f4c7add35a1ab593192869db22dcb86a10865495c67250e3114bce2e0a0f14987972e8b4e5509130feb7e1fbf8f364e2ff855b72884f611932b9";
    validation_hashes["a!_56., "] = "0x80f2912be480e1d516c7bc0c1fb2352ed8047ae293366579ff4637db1776dfd6bea414c1edb75684ce9a9357b2a6d6341eff50870345b72325323c79896a2868";

for (pair<string, string> string_and_hash : validation_hashes)  {
        SHA3_512_Calculator sha3_calculator;
        const string input_string = string_and_hash.first;
        const cpp_int hash_correct      = cpp_int(string_and_hash.second);
        sha3_calculator.hash_message(input_string);
        const cpp_int hash_calculated = sha3_calculator.get_hash();

        cout << "Message: " << input_string << endl;
        cout << "Calculated hash: " << std::hex << hash_calculated << endl;
        cout << "Correct hash:    " << std::hex << hash_correct << endl;

        if (hash_correct != hash_calculated)    {
            throw std::string("Calculated hash does not match the correct hash defined in the test!");
        }
        cout << endl;
    }
}