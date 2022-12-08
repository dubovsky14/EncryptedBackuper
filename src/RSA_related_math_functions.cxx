#include "../EncryptedBackuper/RSA_related_math_functions.h"

using namespace std;
using boost::multiprecision::cpp_int;
using namespace EncryptedBackuper;

vector<cpp_int> EncryptedBackuper::extended_euclidean_algorithm(const cpp_int &a, const cpp_int &b)    {
    if (a == 0) {
        return vector<cpp_int>({b, cpp_int(0), cpp_int(1)});
    }

    vector<cpp_int> prev_result = extended_euclidean_algorithm(cpp_int(b % a), a);
    cpp_int gcd  =  prev_result[0];
    cpp_int x    =  prev_result[1];
    cpp_int y    =  prev_result[2];

    return vector<cpp_int>({gcd, (y - (b/a) * x), x});
};

cpp_int EncryptedBackuper::calculate_private_key(cpp_int euler_phi, cpp_int public_key, bool *key_is_valid)    {
    vector<cpp_int> eua_result = extended_euclidean_algorithm(euler_phi, public_key);
    *key_is_valid = (eua_result[0] == 1);
    cpp_int result =  eua_result[2];
    while (result < 0)  {
        result += euler_phi;
    }
    return result;
};

cpp_int EncryptedBackuper::square_and_multiply(cpp_int base, cpp_int exponent, cpp_int modulo) {
    vector<bool> multiply;

    cpp_int x = exponent;
    while (x > 0)   {
        multiply.push_back(cpp_int(x % 2) == 1);
        x /= 2;
    }

    reverse(multiply.begin(), multiply.end());

    cpp_int result = base;
    for (unsigned int i_bit = 1; i_bit < multiply.size(); i_bit++) {
        result *= result;
        result = cpp_int(result % modulo);

        if (multiply[i_bit])    {
            result *= base;
            result = cpp_int(result % modulo);
        }
    }
    return result;
};

cpp_int EncryptedBackuper::GenerateRandomPrime(RandomNumberGenerator *rng, unsigned int number_of_iterations)   {
    cpp_int result = rng->Random();
    while (!boost::multiprecision::miller_rabin_test(result, number_of_iterations)) {
        result = rng->Random();
    }
    return result;
};

bool EncryptedBackuper::generate_rsa_keys( cpp_int *pq,
                        cpp_int *private_key,
                        const cpp_int &public_key,
                        unsigned int key_size)  {
    RandomNumberGenerator rng(key_size);
    cpp_int p = GenerateRandomPrime(&rng);
    cpp_int q = GenerateRandomPrime(&rng);
    cpp_int phi = (p-1)*(q-1);
    (*pq)  = p*q;

    bool key_is_valid;
    (*private_key) = calculate_private_key(phi, public_key, &key_is_valid);
    return key_is_valid;
};
