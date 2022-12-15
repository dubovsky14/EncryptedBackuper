#pragma once

#include "../AES/aes/AESHandler.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <memory>
#include <vector>

namespace EncryptedBackuper     {
    class AESWrapper   {
        public:
            AESWrapper(const boost::multiprecision::cpp_int &aes_key, int key_length);

            void set_initial_vector(const unsigned char *initial_vector);

            void encrypt(unsigned char *text);

            void encrypt(const unsigned char *plane_text, unsigned char *cipher_text);

            void decrypt(unsigned char *text);

            void decrypt(const unsigned char *cipher_text, unsigned char *plane_text);

        private:
            unsigned char m_initial_vector[16];
            unsigned char m_state[16];

            std::shared_ptr<AES::AESHandler>    m_aes_handler = nullptr;

            static std::vector<unsigned char>   cpp_int_to_unsigned_char_vector(const boost::multiprecision::cpp_int &number);
    };
}