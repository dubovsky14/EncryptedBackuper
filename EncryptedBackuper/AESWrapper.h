#pragma once

#include "../AES/aes/AESHandler.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <memory>
#include <vector>

namespace EncryptedBackuper     {
    class AESWrapper   {
        public:

            /* iv_mode = true means that when running th encryption of (N+1)-th block, the plain text from N+1 block will be firstly XOR-ed with encrypted text from N-th block */
            AESWrapper(const boost::multiprecision::cpp_int &aes_key, int key_length, bool iv_mode = true);

            void encrypt(unsigned char *text);

            void encrypt(const unsigned char *plain_text, unsigned char *cipher_text);

            void decrypt(unsigned char *text);

            void decrypt(const unsigned char *cipher_text, unsigned char *plain_text);

            void xor_with_iv(unsigned char *text);

            void xor_with_iv_and_store_in_iv(const unsigned char *text);

        private:
            unsigned char m_initial_vector[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
            unsigned char m_buffer[16];

            bool m_iv_mode;

            std::shared_ptr<AES::AESHandler>    m_aes_handler = nullptr;

            static std::vector<unsigned char>   cpp_int_to_unsigned_char_vector(const boost::multiprecision::cpp_int &number);
    };
}