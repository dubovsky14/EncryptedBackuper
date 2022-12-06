#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/RandomNumberGenerator.h"
#include <boost/multiprecision/cpp_int.hpp>

#include <iostream>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

int main(int argc, const char **argv)   {

    long long int pq, private_key, public_key(17);
    if (!generate_rsa_keys(&pq, &private_key, public_key))
        cout << "Invalid key!\n";

    cout << "pq = " << pq << endl;
    cout << "key_private = " << private_key << endl;
    cout << "key_public = " << public_key << endl;

    while (true)    {
        long long int message;
        cout << "Set the message\n";
        cin >> message;
        cout << endl;


        long long int signature = square_and_multiply(message, private_key, pq);
        cout << "signature = " << signature << endl;

        long long int signature_decr = square_and_multiply(signature, public_key, pq);
        cout << "signature^pub_key mod pq = " << signature_decr << endl;
    }
/*
    RandomNumberGenerator<unsigned long long int> rng;
    for (unsigned int i = 0; i < 10; i++)   {
        cout << GenerateRandomPrime(&rng, 25) << endl;
    }
    return 0;

    const long long int p(991), q(691);
    const long long int pq = q*p;;

    const long long int phi = (p-1)*(q-1);
    const long long int pub_key = 17;

    bool valid_key = true;
    const long long int private_key = calculate_private_key(phi, pub_key, &valid_key);
    cout << "Private key = " << private_key << endl;

    const long long int message = 31;
    const long long int signature = square_and_multiply(message, private_key, pq);

    cout << "message = " << message << "\t\tsignature = " << signature << endl;
    cout << "signature^pub mod pq = " << square_and_multiply(signature, pub_key, pq) << endl;
*/

    return 0;
}