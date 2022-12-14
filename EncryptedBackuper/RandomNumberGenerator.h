#pragma once

#include <random>
#include <vector>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
namespace EncryptedBackuper     {
    // TODO: Check security of this
    /* Cryptographically safe random number generator. For now just placeholder, safety will be inspected and possibly improved.  */

    class RandomNumberGenerator {
        public:
            /* Random number generator, returning a random number with uniform distribution from 0 to (2^return_size - 1), i.e. return_size-bit long number*/
            RandomNumberGenerator(unsigned int return_size) {
                if (return_size % 32 != 0)    {
                    throw std::string("RandomnumberGenerator: Invalid return size, only multiples of 32 are allowed!");
                }
                m_size_of_return_type = return_size;
            };

            boost::multiprecision::cpp_int Random()    {
                boost::multiprecision::cpp_int result = 0;
                for (unsigned int i_block = 0; i_block < m_size_of_return_type/32; i_block++)   {
                    result *= 0x100000000;
                    result += m_rd() % 0x100000000;
                }
                return result;
            };

            RandomNumberGenerator()                                 = delete;
            RandomNumberGenerator(const RandomNumberGenerator& x)   = delete;

        private:
            unsigned int                m_size_of_return_type;
            std::random_device          m_rd;
    };
}