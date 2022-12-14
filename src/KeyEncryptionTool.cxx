#include "../EncryptedBackuper/KeyEncryptionTool.h"

#include "../EncryptedBackuper/SHA3Calculator.h"
#include "../EncryptedBackuper/RandomNumberGenerator.h"
#include "../EncryptedBackuper/RSA_related_math_functions.h"


#include <boost/multiprecision/cpp_int.hpp>


#include <string>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

void KeyEncryptionTool::set_rsa_keys(  const boost::multiprecision::cpp_int &pq,
                    const boost::multiprecision::cpp_int &public_key,
                    const boost::multiprecision::cpp_int &private_key_xor_password_hash,
                    unsigned int rsa_key_size)  {
    m_pq                            = pq;
    m_public_key                    = public_key;
    m_private_key_xor_password_hash = private_key_xor_password_hash;
    m_rsa_key_size                  = rsa_key_size;
};


boost::multiprecision::cpp_int KeyEncryptionTool::generate_aes_key(const std::string &file_hashes_summary) const    {
    RandomNumberGenerator rng(256);
    const string random_number = convert_cpp_int_to_hex_string(rng.Random());

    return calculate_sha3(random_number + file_hashes_summary, 256);
};

boost::multiprecision::cpp_int KeyEncryptionTool::encrypt_aes_key(const boost::multiprecision::cpp_int &aes_key)    {
    if (aes_key > m_pq) {
        throw std::string("KeyEncryptionTool::encrypt_aes_key: Unable to exncrypt. The provided AES key is larger than P*Q expresion in RSA key");
    }
    return square_and_multiply(aes_key, m_public_key, m_pq);
};

boost::multiprecision::cpp_int KeyEncryptionTool::decrypt_aes_key(const std::string &password)  {

};

std::string KeyEncryptionTool::get_key_summary_string()    const    {

};

void KeyEncryptionTool::load_key_summary_string(const std::string key_summary_string, const std::string &password)  const   {

};

boost::multiprecision::cpp_int  KeyEncryptionTool::encrypt_private_key( const boost::multiprecision::cpp_int &private_key,
                                                                        const std::string &password, unsigned int rsa_type) {

    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, rsa_type);
    return private_key ^ password_extended_hash;
};

boost::multiprecision::cpp_int  KeyEncryptionTool::decrypt_private_key( const boost::multiprecision::cpp_int &private_key_encrypted,
                                                                        const std::string &password, unsigned int rsa_type) {

    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, rsa_type);
    return private_key_encrypted ^ password_extended_hash;
};


boost::multiprecision::cpp_int  KeyEncryptionTool::generate_rsa_bit_length_size_password_hash(  const std::string &password,
                                                                                                unsigned int rsa_key_length)    {

    const unsigned int sha3_type = 512;
    SHA3Calculator password_hasher(sha3_type);
    password_hasher.hash_message(password);
    cpp_int password_extended_hash = password_hasher.get_hash();
    const unsigned int required_number_of_hashes = rsa_key_length/sha3_type;
    const cpp_int bitshift_constant = square_and_multiply(cpp_int(2), sha3_type, 0);
    for (unsigned int i = 1; i<required_number_of_hashes; i++)   {
        password_extended_hash *= bitshift_constant;
        password_extended_hash += password_hasher.apply_next_keccak_and_get_output();
    }
    return password_extended_hash;
};