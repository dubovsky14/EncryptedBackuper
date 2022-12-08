#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/RandomNumberGenerator.h"
#include <boost/multiprecision/cpp_int.hpp>

#include <iostream>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

int main(int argc, const char **argv)   {


    boost::multiprecision::cpp_int pq, private_key, public_key(65537);

    bool valid_key = false;
    while (!valid_key) {
        valid_key = generate_rsa_keys(&pq, &private_key, public_key, 512);
    }
    cout << "pq = " << pq << endl;
    cout << "key_private = " << private_key << endl;
    cout << "key_public = " << public_key << endl;

    while (true)    {
        boost::multiprecision::cpp_int message;
        cout << "Set the message\n";
        cin >> message;
        cout << endl;

        const boost::multiprecision::cpp_int signature = square_and_multiply(message, private_key, pq);
        cout << "signature = " << signature << endl;

        const boost::multiprecision::cpp_int signature_decr = square_and_multiply(signature, public_key, pq);
        cout << "signature^pub_key mod pq = " << signature_decr << endl;
    }

    return 0;
/*
    RandomNumberGenerator rng(2048);
    for (unsigned int i = 0; i < 10; i++)   {
        cout << GenerateRandomPrime(&rng, 25) << endl;
    }
    return 0;

    cpp_int p(991), q(691);
    cpp_int pq = q*p;;

    cpp_int phi = (p-1)*(q-1);
    cpp_int pub_key = 17;

    bool valid_key = true;
    cpp_int private_key = calculate_private_key(phi, pub_key, &valid_key);
    cout << "Private key = " << private_key << endl;

    cpp_int message = 31;
    cpp_int signature = square_and_multiply(message, private_key, pq);

    cout << "message = " << message << "\t\tsignature = " << signature << endl;
    cout << "signature^pub mod pq = " << square_and_multiply(signature, pub_key, pq) << endl;

    return 0;
*/
}