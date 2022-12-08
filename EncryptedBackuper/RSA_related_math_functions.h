#pragma once

#include "../EncryptedBackuper/RandomNumberGenerator.h"

#include <tuple>
#include <vector>
#include <iostream>
#include <bits/stdc++.h>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace EncryptedBackuper     {

    /**
     * @brief Returns vector of 3 elements: (GCD(a,b), x, y), where x*a + y*b = GCD(a,b)
     */
    std::vector<boost::multiprecision::cpp_int> extended_euclidean_algorithm(const boost::multiprecision::cpp_int &a, const boost::multiprecision::cpp_int &b)    {
        if (a == 0) {
            return std::vector<boost::multiprecision::cpp_int>({b, boost::multiprecision::cpp_int(0), boost::multiprecision::cpp_int(1)});
        }

        boost::multiprecision::cpp_int b_mod_a(b % a);
        auto prev_result = extended_euclidean_algorithm(b_mod_a, a);
        boost::multiprecision::cpp_int gcd  =  prev_result[0];
        boost::multiprecision::cpp_int x    =  prev_result[1];
        boost::multiprecision::cpp_int y    =  prev_result[2];


        return std::vector<boost::multiprecision::cpp_int>({gcd, (y - (b/a) * x), x});
    };

    /**
     * Function calculating a private key from the given public key and value of Euler phi function.
     * If greatest common denominator of euler_phi and public_key is not 1, the public key does not exist (value of key_is_valid will be set to false, otherwise it's true).
    */
    boost::multiprecision::cpp_int calculate_private_key(boost::multiprecision::cpp_int euler_phi, boost::multiprecision::cpp_int public_key, bool *key_is_valid)    {
        std::vector<boost::multiprecision::cpp_int> eua_result = extended_euclidean_algorithm(euler_phi, public_key);
        *key_is_valid = (eua_result[0] == 1);
        boost::multiprecision::cpp_int result =  eua_result[2];
        while (result < 0)  {
            result += euler_phi;
        }
        return result;
    };

    /* Square and multiply algorithm. It returns "pow(base, exponent) % modulo" */
    boost::multiprecision::cpp_int square_and_multiply(boost::multiprecision::cpp_int base, boost::multiprecision::cpp_int exponent, boost::multiprecision::cpp_int modulo) {
        std::vector<bool> multiply;

        boost::multiprecision::cpp_int x = exponent;
        while (x > 0)   {
            multiply.push_back(boost::multiprecision::cpp_int(x % 2) == 1);
            x /= 2;
        }

        std::reverse(multiply.begin(), multiply.end());

        boost::multiprecision::cpp_int result = base;
        for (unsigned int i_bit = 1; i_bit < multiply.size(); i_bit++) {
            result *= result;
            result = boost::multiprecision::cpp_int(result % modulo);

            if (multiply[i_bit])    {
                result *= base;
                result = boost::multiprecision::cpp_int(result % modulo);
            }
        }
        return result;
    };

    boost::multiprecision::cpp_int GenerateRandomPrime(RandomNumberGenerator *rng, unsigned int number_of_iterations = 50)   {
        boost::multiprecision::cpp_int result = rng->Random();
        while (!boost::multiprecision::miller_rabin_test(result, number_of_iterations)) {
            result = rng->Random();
        }
        return result;
    };


    /*
    Generate 2 prime numbers P and Q, randomly chooses private key
    If key2 and (p-1)*(q-1) are not relative primes, i.e. the key2 cannot be used, it.
    Public key must be a prime number
    */
    bool generate_rsa_keys( boost::multiprecision::cpp_int *pq,
                            boost::multiprecision::cpp_int *private_key,
                            const boost::multiprecision::cpp_int &public_key,
                            unsigned int key_size = 1024)  {
        RandomNumberGenerator rng(key_size);
        boost::multiprecision::cpp_int p = GenerateRandomPrime(&rng);
        boost::multiprecision::cpp_int q = GenerateRandomPrime(&rng);
        boost::multiprecision::cpp_int phi = (p-1)*(q-1);
        (*pq)  = p*q;

        bool key_is_valid;
        (*private_key) = calculate_private_key(phi, public_key, &key_is_valid);
        return key_is_valid;
    };
}
