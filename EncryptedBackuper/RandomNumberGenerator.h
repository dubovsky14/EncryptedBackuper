#pragma once

#include <random>
#include <vector>
namespace EncryptedBackuper     {
    /* Cryptographically safe random number generator. For now just placeholder, safety will be inspected and possibly improved.  */
    template<class IntType>
    class RandomNumberGenerator {
        public:
            RandomNumberGenerator() {
                m_size_of_return_type = sizeof(IntType);
                m_generated_values.resize(m_size_of_return_type/sizeof(unsigned int) + 1);
            };

            IntType Random()    {
                for (auto &x : m_generated_values)  {
                    x = m_rd();
                }
                const IntType result = *(reinterpret_cast<IntType *>(&m_generated_values[0]));
                if (result > 0) {
                    return result;
                }
                return Random();
            };

            RandomNumberGenerator(const RandomNumberGenerator& x)   = delete;

        private:
            size_t                      m_size_of_return_type;
            std::vector<unsigned int>   m_generated_values;
            std::random_device          m_rd;
    };
}