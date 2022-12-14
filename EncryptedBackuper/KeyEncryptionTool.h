#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <string>

namespace EncryptedBackuper     {
    class KeyEncryptionTool   {
        public:
            void set_rsa_keys(  const boost::multiprecision::cpp_int &pq,
                                const boost::multiprecision::cpp_int &public_key,
                                const boost::multiprecision::cpp_int &private_key_xor_password_hash,
                                unsigned int rsa_key_size);


            boost::multiprecision::cpp_int generate_aes_key(const std::string &file_hashes_summary) const;

            boost::multiprecision::cpp_int encrypt_aes_key(const boost::multiprecision::cpp_int &aes_key);

            boost::multiprecision::cpp_int decrypt_aes_key(const std::string &password);

            std::string get_key_summary_string()    const;

            void load_key_summary_string(const std::string key_summary_string, const std::string &password)  const;

            /* XOR private key and the hash of the password */
            static boost::multiprecision::cpp_int  encrypt_private_key( const boost::multiprecision::cpp_int &private_key,
                                                                        const std::string &password, unsigned int rsa_type);

            static boost::multiprecision::cpp_int  decrypt_private_key( const boost::multiprecision::cpp_int &private_key_encrypted,
                                                                        const std::string &password, unsigned int rsa_type);


            /* Calculate pseudo-random number using SHA3-512 with the bith length equal to rsa_key_length */
            static boost::multiprecision::cpp_int  generate_rsa_bit_length_size_password_hash(  const std::string &password,
                                                                                                unsigned int rsa_key_length);
        private:
            boost::multiprecision::cpp_int  m_pq;
            boost::multiprecision::cpp_int  m_public_key;
            boost::multiprecision::cpp_int  m_private_key_xor_password_hash;
            unsigned int                    m_rsa_key_size;

            boost::multiprecision::cpp_int  m_aes_key = -1;


    };
}