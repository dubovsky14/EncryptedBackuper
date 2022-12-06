#include "../EncryptedBackuper/RSA_related_math_functions.h"

#include <iostream>

using namespace std;
using namespace EncryptedBackuper;

int main(int argc, const char **argv)   {
    const long long int p(991), q(691);
    const long long int pq = q*p;;

    const long long int phi = (p-1)*(q-1);
    const long long int pub_key = 17;

    const long long int private_key = calculate_private_key(phi, pub_key);
    cout << "Private key = " << private_key << endl;

    const long long int message = 31;
    const long long int signature = square_and_multiply(message, private_key, pq);

    cout << "message = " << message << "\t\tsignature = " << signature << endl;
    cout << "signature^pub mod pq = " << square_and_multiply(signature, pub_key, pq) << endl;


    return 0;
}