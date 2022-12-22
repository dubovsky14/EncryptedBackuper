#include "../EncryptedBackuper/RSA_related_math_functions.h"

using namespace std;
using boost::multiprecision::cpp_int;
using namespace EncryptedBackuper;

vector<cpp_int> EncryptedBackuper::extended_euclidean_algorithm(const cpp_int &a, const cpp_int &b)    {
    if (a == 0) {
        return vector<cpp_int>({b, cpp_int(0), cpp_int(1)});
    }

    const vector<cpp_int> prev_result = extended_euclidean_algorithm(cpp_int(b % a), a);
    const cpp_int gcd  =  prev_result[0];
    const cpp_int x    =  prev_result[1];
    const cpp_int y    =  prev_result[2];

    return vector<cpp_int>({gcd, (y - (b/a) * x), x});
};

cpp_int EncryptedBackuper::calculate_private_key(const cpp_int &euler_phi, const cpp_int &public_key, bool *key_is_valid)    {
    vector<cpp_int> ext_euclid_result = extended_euclidean_algorithm(euler_phi, public_key);
    *key_is_valid = (ext_euclid_result[0] == 1);    // checking if euler_phi and public_key are relative primes (i.e. gcd == 1)
    cpp_int private_key =  ext_euclid_result[2];
    while (private_key < 0)  {
        private_key += euler_phi;
    }
    return private_key;
};

cpp_int EncryptedBackuper::square_and_multiply(const cpp_int &base, const cpp_int &exponent, const cpp_int &modulo) {
    vector<unsigned char> binary_representation = get_representation_in_base_n(exponent, 2);

    cpp_int result = base;
    for (unsigned int i_bit = 1; i_bit < binary_representation.size(); i_bit++) {
        result *= result;
        if (modulo != 0)    {
            result = cpp_int(result % modulo);
        }

        if (binary_representation[i_bit])    {
            result *= base;
            if (modulo != 0)    {
                result = cpp_int(result % modulo);
            }
        }
    }
    return result;
};

cpp_int EncryptedBackuper::generate_random_prime(RandomNumberGenerator *rng, unsigned int number_of_iterations)   {
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
    RandomNumberGenerator rng(key_size/2);
    const cpp_int p = generate_random_prime(&rng);
    const cpp_int q = generate_random_prime(&rng);
    const cpp_int euler_phi = (p-1)*(q-1);
    (*pq)  = p*q;

    bool key_is_valid;
    (*private_key) = calculate_private_key(euler_phi, public_key, &key_is_valid);
    return key_is_valid;
};

vector<unsigned char> EncryptedBackuper::get_representation_in_base_n(const cpp_int &number, unsigned char base)   {
    vector<unsigned char> result;
    cpp_int x = number;
    while (x > 0)   {
        result.push_back((unsigned char)(x % base));
        x = cpp_int(x/base);
    }
    reverse(result.begin(), result.end());
    return result;
};

std::string EncryptedBackuper::convert_cpp_int_to_hex_string(const boost::multiprecision::cpp_int &number) {
    const string hex_chars("0123456789abcdef");
    string result = "";
    vector<unsigned char> hex_representation = get_representation_in_base_n(number, 16);
    for (unsigned char x : hex_representation)  {
        result = result+hex_chars[x];
    }
    return result;
};

std::string EncryptedBackuper::convert_cpp_int_to_bin_string(const boost::multiprecision::cpp_int &number) {
    const string bin_chars("01");
    string result = "";
    vector<unsigned char> bin_representation = get_representation_in_base_n(number, 2);
    for (unsigned char x : bin_representation)  {
        result = result+bin_chars[x];
    }
    return result;
};