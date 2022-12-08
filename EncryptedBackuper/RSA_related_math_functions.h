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
    std::vector<boost::multiprecision::cpp_int> extended_euclidean_algorithm(   const boost::multiprecision::cpp_int &a,
                                                                                const boost::multiprecision::cpp_int &b);

    /**
     * Function calculating a private key from the given public key and value of Euler phi function.
     * If greatest common denominator of euler_phi and public_key is not 1, the public key does not exist (value of key_is_valid will be set to false, otherwise it's true).
    */
    boost::multiprecision::cpp_int calculate_private_key(   const boost::multiprecision::cpp_int &euler_phi,
                                                            const boost::multiprecision::cpp_int &public_key,
                                                            bool *key_is_valid);

    /* Square and multiply algorithm. It returns "pow(base, exponent) % modulo" */
    boost::multiprecision::cpp_int square_and_multiply( const boost::multiprecision::cpp_int &base,
                                                        const boost::multiprecision::cpp_int &exponent,
                                                        const boost::multiprecision::cpp_int &modulo);

    boost::multiprecision::cpp_int generate_random_prime( RandomNumberGenerator *rng,
                                                        unsigned int number_of_iterations = 50);


    /*
    Generate 2 prime numbers P and Q, randomly chooses private key
    If key2 and (p-1)*(q-1) are not relative primes, i.e. the key2 cannot be used, and false value is returned (key not found).
    It's up to user not to use someting dumb, such as public_key = 2.
    */
    bool generate_rsa_keys( boost::multiprecision::cpp_int *pq,
                            boost::multiprecision::cpp_int *private_key,
                            const boost::multiprecision::cpp_int &public_key,
                            unsigned int key_size = 1024);

    /* Get representation of the number in base "base", i.e. binary for (base=2)*/
    std::vector<unsigned char> get_representation_in_base_n(const boost::multiprecision::cpp_int &number, unsigned char base);
}