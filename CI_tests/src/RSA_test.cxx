#include "../../CI_tests/headers/RSA_test.h"

#include "../../EncryptedBackuper/RSA_related_math_functions.h"
#include "../../EncryptedBackuper/RandomNumberGenerator.h"
#include <boost/multiprecision/cpp_int.hpp>

#include <iostream>
#include <string>

using namespace std;
using namespace EncryptedBackuper;
using namespace EncryptedBackuperTests;
using namespace boost::multiprecision;

void EncryptedBackuperTests::RSA_test(unsigned int key_length)   {
    boost::multiprecision::cpp_int pq, private_key, public_key(65537);

    bool valid_key = false;
    unsigned int key_attempt = 0;
    while (!valid_key && key_attempt < 100) {
        valid_key = generate_rsa_keys(&pq, &private_key, public_key, key_length);
        key_attempt++;
    }

    if (!valid_key) {
        throw std::string("Unable to generate RSA pair of keys!");
    }

    cout << "pq = " << pq << endl;
    cout << "key_private = " << private_key << endl;
    cout << "key_public = " << public_key << endl << endl;

    RandomNumberGenerator rng(key_length/2);
    for (unsigned int i = 0; i < 10; i++)    {
        boost::multiprecision::cpp_int message = rng.Random();
        cout << "Message = " << message << endl;

        const boost::multiprecision::cpp_int signature = square_and_multiply(message, private_key, pq);
        cout << "signature = " << signature << endl;

        const boost::multiprecision::cpp_int signature_decr = square_and_multiply(signature, public_key, pq);
        cout << "signature^pub_key mod pq = " << signature_decr << endl << endl;

        if (message != signature_decr)  {
            throw string("Invalid RSA signature!");
        }
    }
}