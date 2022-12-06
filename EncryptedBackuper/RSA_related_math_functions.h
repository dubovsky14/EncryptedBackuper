#pragma once

#include "../EncryptedBackuper/RandomNumberGenerator.h"

#include <tuple>
#include <vector>
#include <iostream>
#include <bits/stdc++.h>
#include <boost/multiprecision/miller_rabin.hpp>

namespace EncryptedBackuper     {

    /**
     * @brief Returns tuple of <GCD(a,b), x, y>, where x*a + y*b = GCD(a,b)
     */
    template<class IntType>
    std::tuple<IntType, IntType, IntType> extended_euclidean_algorithm(IntType a, IntType b)    {
        if (a == 0) {
             return std::make_tuple(b, 0, 1);
        }

        IntType gcd, x, y;
        std::tie(gcd, x, y) = extended_euclidean_algorithm(b % a, a);

        return std::make_tuple(gcd, (y - (b/a) * x), x);
    };

    /**
     * Function calculating a private key from the given public key and value of Euler phi function.
     * If greatest common denominator of euler_phi and public_key is not 1, the public key does not exist (value of key_is_valid will be set to false, otherwise it's true).
    */
    template<class IntType>
    IntType calculate_private_key(IntType euler_phi, IntType public_key, bool *key_is_valid)    {
        std::tuple<IntType, IntType, IntType> eua_result = extended_euclidean_algorithm(euler_phi, public_key);
        *key_is_valid = (std::get<0>(eua_result) == 1);
        IntType result = std::get<2>(eua_result);
        while (result < 0)  {
            result += euler_phi;
        }
        return result;
    };

    /* Square and multiply algorithm. It returns "pow(base, exponent) % modulo" */
    template<class IntType>
    IntType square_and_multiply(IntType base, IntType exponent, IntType modulo) {
        const unsigned int nbits_exponent = sizeof(exponent);
        std::vector<bool> multiply;

        IntType x = exponent;
        while (x > 0)   {
            multiply.push_back(x % 2);
            x /= 2;
        }

        std::reverse(multiply.begin(), multiply.end());

        IntType result = base;
        for (unsigned int i_bit = 1; i_bit < multiply.size(); i_bit++) {
            result *= result;
            result = result % modulo;

            if (multiply[i_bit])    {
                result *= base;
                result = result % modulo;
            }
        }
        return result;
    };

    template<class IntType>
    IntType GenerateRandomPrime(RandomNumberGenerator<IntType> *rng, unsigned int number_of_iterations = 50)   {
        IntType result = rng->Random();
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
    template<class IntType>
    bool generate_rsa_keys(IntType *pq, IntType *private_key, const IntType &public_key)  {
        RandomNumberGenerator<unsigned int> rng_u32;
        IntType p = GenerateRandomPrime(&rng_u32);
        IntType q = GenerateRandomPrime(&rng_u32);
        IntType phi = (p-1)*(q-1);
        (*pq)  = p*q;

        bool key_is_valid;
        (*private_key) = calculate_private_key(phi, public_key, &key_is_valid);
        return key_is_valid;
    };

/*
    template<class IntType>
    bool is_prime_number(IntType number, int number_of_iterations = 5)    {
        if (number % 2 == 0 && number != 2)     return false;
        if (number == 3)                        return true;

        int s = 0;
        IntType d = n - 1;
        while ((d & 1) == 0) {
            d >>= 1;
            s++;
        }

        for (int i = 0; i < iter; i++) {
            int a = 2 + rand() % (n - 3);
            if (check_composite(n, a, d, s))
                return false;
        }
        return true;
    };

    template<class IntType>
    bool check_composite(IntType n, IntType a, IntType d, int s) {
        IntType x = square_and_multiply(a, d, n);
        if (x == 1 || x == n - 1)
            return false;
        for (int r = 1; r < s; r++) {
            x = x * x % n;
            if (x == n - 1)
                return false;
        }
        return true;
    };
*/

}
