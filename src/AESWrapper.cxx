#include "../EncryptedBackuper/AESWrapper.h"

#include "../AES/aes/EncryptIteration.h"

#include <boost/multiprecision/cpp_int.hpp>

using namespace EncryptedBackuper;
using namespace std;
using namespace AES;
using boost::multiprecision::cpp_int;

AESWrapper::AESWrapper(const boost::multiprecision::cpp_int &aes_key, int key_length, bool iv_mode) {
    m_iv_mode = iv_mode;
    if (key_length != 128 && key_length != 192 && key_length != 256)   {
        throw std::string("AESHandler::Invalid key size: " + std::to_string(key_length) + " bits");
    }
    const unsigned key_length_bytes = key_length/8;
    std::vector<unsigned char> key_uchar_vector = cpp_int_to_unsigned_char_vector(aes_key);
    if (key_uchar_vector.size() > key_length_bytes)     {
        throw std::string("AESHandler:: AES key is too long");
    }
    while (key_uchar_vector.size() < key_length_bytes)  {
        key_uchar_vector.insert(key_uchar_vector.begin(), 0);
    }
    m_aes_handler = make_shared<AESHandler>(&key_uchar_vector[0], key_length);
};

void AESWrapper::xor_with_iv(unsigned char *text)   {
    *(reinterpret_cast<uint64_t *>(&text[0])) = *(reinterpret_cast<const uint64_t *>(&text[0])) ^ *(reinterpret_cast<const uint64_t *>(&m_initial_vector[0]));
    *(reinterpret_cast<uint64_t *>(&text[8])) = *(reinterpret_cast<const uint64_t *>(&text[8])) ^ *(reinterpret_cast<const uint64_t *>(&m_initial_vector[8]));
};

void AESWrapper::xor_with_iv_and_store_in_iv(const unsigned char *text)   {
    *(reinterpret_cast<uint64_t *>(&m_initial_vector[0])) = *(reinterpret_cast<const uint64_t *>(&text[0])) ^ *(reinterpret_cast<const uint64_t *>(&m_initial_vector[0]));
    *(reinterpret_cast<uint64_t *>(&m_initial_vector[8])) = *(reinterpret_cast<const uint64_t *>(&text[8])) ^ *(reinterpret_cast<const uint64_t *>(&m_initial_vector[8]));
};

void AESWrapper::encrypt(unsigned char *text)   {
    if (!m_iv_mode)    {
        m_aes_handler->Encrypt(text);
    }
    else {
        xor_with_iv(text);
        m_aes_handler->Encrypt(text);
        memcpy(m_initial_vector, text, 16);
    }
};

void AESWrapper::encrypt(const unsigned char *plain_text, unsigned char *cipher_text)   {
    if (!m_iv_mode)    {
        m_aes_handler->Encrypt(plain_text, cipher_text);
    }
    else {
        xor_with_iv_and_store_in_iv(plain_text);
        m_aes_handler->Encrypt(m_initial_vector);
        memcpy(cipher_text, m_initial_vector, 16);
    }
};

void AESWrapper::decrypt(const unsigned char *cipher_text, unsigned char *plain_text)   {
    if (!m_iv_mode)    {
        m_aes_handler->Decrypt(cipher_text,plain_text);
    }
    else {
        memcpy(plain_text, cipher_text, 16);
        m_aes_handler->Decrypt(plain_text);
        xor_with_iv(plain_text);
        memcpy(m_initial_vector, plain_text, 16);
    }
};

void AESWrapper::decrypt(unsigned char *text)   {
    if (!m_iv_mode)    {
        m_aes_handler->Decrypt(text);
    }
    else {
        memcpy(m_buffer, text, 16);
        m_aes_handler->Decrypt(text);
        xor_with_iv(text);
        memcpy(m_initial_vector, m_buffer, 16);
    }
};

std::vector<unsigned char>   AESWrapper::cpp_int_to_unsigned_char_vector(const boost::multiprecision::cpp_int &number)   {
    vector<unsigned char> result;
    cpp_int x = number;
    while (x > 0)   {
        result.push_back((unsigned char)(x % 256));
        x = cpp_int(x/256);
    }
    reverse(result.begin(), result.end());
    return result;
};
