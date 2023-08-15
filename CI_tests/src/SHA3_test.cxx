#include "../../CI_tests/headers/SHA3_test.h"

#include "../../EncryptedBackuper/SHA3Calculator.h"
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

void EncryptedBackuperTests::SHA3_test_sample_strings(unsigned int sha_type)  {
    cout << "Going to run the test for SHA3-" << sha_type << ".\n";

    vector< map<int,string> >   sample_hashes({
        {
            {0  , ""},
            {224, "0x6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
            {256, "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
            {384, "0x0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
            {512, "0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"}
        },
        {
            {0  , "We shall go on to the end. We shall fight in France, we shall fight on the seas and oceans. We shall fight with growing confidence and growing strength in the air, we shall defend our island, whatever the cost may be. We shall fight on the beaches, we shall fight on the landing grounds. We shall fight in the fields, and in the streets. We shall fight in the hills. We shall never surrender!"},
            {224, "0x57cd157197d46e64b9b8267f3a3c59cd70447fe4abb8c90ade70179f"},
            {256, "0x57992345ee920a2d3f1173042c66d5aedd9402ec38d872b7a394e3431901301a"},
            {384, "0x07f9366c70e202b2137435841452384ed1b28a5eb2b51ff7767cb128eeb8082e4a047db839b95a52e46c5d2905539c8b"},
            {512, "0x58e0297eca60f4c7add35a1ab593192869db22dcb86a10865495c67250e3114bce2e0a0f14987972e8b4e5509130feb7e1fbf8f364e2ff855b72884f611932b9"}
        },
        {
            {0  , "a!_56., @#457569,/;';]["},
            {224, "0x957ffd354a35f24be34f1be62f2ad6cc9d95cce7339bb0d6b4237cb8"},
            {256, "0xbec2625db6cfbd3bf79de642209a7375df4ed88e96438991ab9026c2d66c8f0b"},
            {384, "0x00155b5a1ef674001d876b64107402f5fd9f8be7266bbc08a9670857f763d8946188dcbe2cb90f33765767d7245bb0bc"},
            {512, "0x691f36968d433846f7af8802c0fcc995f7fbb1cf33543770e8d181de562c90e81f4e1db77ef93d5ba86106d9ce4268b8ebd6057d466b0cf26da70b6e9747134c"}
        },
        {
            {0  , "Ja si televizor zoberem a pojdem na rieku Nitru pozerat!"},
            {224, "0x255d6afed1cd32373dbea23c6f6aa628a168e115bef2f5a201896ff8"},
            {256, "0xc724e666108d629cf66197f8067a3b6808fcd4773618b80e15e2f4f7f30d2061"},
            {384, "0xf51cb4edc5c7d4f460a4a89333895b726da2362617254c95e6f7c168a331868d396e3014ae75ecd543e6c7e60d838006"},
            {512, "0x30196c1003ad75f3d3e6f8718a757a0d52b0390a0425eb22d59558cc6b799e641c8f27e2a0d18ab69724a236b1b74db9a146ea70097f0ef6bef3b10626d5c493"}
        },
    });


    for (map<int,string> string_and_hashes : sample_hashes)  {
        const string input_string = string_and_hashes[0];
        const cpp_int hash_correct      = cpp_int(string_and_hashes[sha_type]);
        const cpp_int hash_calculated   = calculate_sha3(input_string, sha_type);

        cout << "Message: " << input_string << endl;
        cout << "Calculated hash: " << std::hex << hash_calculated << endl;
        cout << "Correct hash:    " << std::hex << hash_correct << endl;

        if (hash_correct != hash_calculated)    {
            throw std::string("Calculated hash does not match the correct hash defined in the test!");
        }
        cout << endl;
    }
}

void EncryptedBackuperTests::SHA3_test_file(unsigned int sha_type, int argc, const char **argv)  {
    if (argc != 4)  {
        throw std::string("Three input arguments are required! Test type, file address and hash");
    }
    cout << "Going to run the test for SHA3-" << sha_type << ".\n";

    const string file_address = argv[2];
    const cpp_int hash_correct      = cpp_int(string(argv[3]));
    const cpp_int hash_calculated   = calculate_sha3_from_file(file_address, sha_type);

    cout << "File: " << file_address << endl;
    cout << "Calculated hash: " << std::hex << hash_calculated << endl;
    cout << "Correct hash:    " << std::hex << hash_correct << endl;

    if (hash_correct != hash_calculated)    {
        throw std::string("Calculated hash does not match the correct hash defined in the test!");
    }
    cout << endl;
};