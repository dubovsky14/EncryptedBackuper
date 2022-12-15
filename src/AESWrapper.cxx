#include "../EncryptedBackuper/AESWrapper.h"

#include "../AES/aes/EncryptIteration.h"

#include <boost/multiprecision/cpp_int.hpp>

using namespace EncryptedBackuper;
using namespace std;
using namespace AES;
using boost::multiprecision::cpp_int;

AESWrapper::AESWrapper(const boost::multiprecision::cpp_int &aes_key, int key_length) {
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

void AESWrapper::set_initial_vector(const unsigned char *initial_vector)    {

};

void AESWrapper::encrypt(unsigned char *text)   {
    m_aes_handler->Encrypt(text);
};

void AESWrapper::encrypt(const unsigned char *plane_text, unsigned char *cipher_text)   {
    m_aes_handler->Encrypt(plane_text, cipher_text);
};

void AESWrapper::decrypt(const unsigned char *cipher_text, unsigned char *plane_text)   {
    m_aes_handler->Decrypt(cipher_text,plane_text);
};

void AESWrapper::decrypt(unsigned char *text)   {
    m_aes_handler->Decrypt(text);
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
