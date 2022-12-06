#pragma once

#include <tuple>
#include <vector>
#include <iostream>
#include <bits/stdc++.h>

namespace EncryptedBackuper     {
    template<class IntType>
    std::tuple<IntType, IntType, IntType> extended_euclidean_algorithm(IntType a, IntType b)    {
        if (a == 0) {
             return std::make_tuple(b, 0, 1);
        }

        IntType gcd, x, y;
        std::tie(gcd, x, y) = extended_euclidean_algorithm(b % a, a);

        return std::make_tuple(gcd, (y - (b/a) * x), x);
    };

    template<class IntType>
    IntType calculate_private_key(IntType euler_phi, IntType public_key)    {
        std::tuple<IntType, IntType, IntType> eua_result = extended_euclidean_algorithm(euler_phi, public_key);
        IntType result = std::get<2>(eua_result);
        while (result < 0)  {
            result += euler_phi;
        }
        return result;
    };

    template<class IntType>
    IntType square_and_multiply(IntType base, IntType exponent, IntType modulo) {
        const unsigned int nbits_exponent = sizeof(exponent);
        std::vector<bool> multiply;
        //multiply.reserve(sizeof(exponent));

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

}
