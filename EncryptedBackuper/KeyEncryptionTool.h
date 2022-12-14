#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <string>

namespace EncryptedBackuper     {

    /* Class responsible for key encryption.
    Using Keccak function from SHA3-5125the hash of the password, it XOR it with RSA private key and store this as encrypted private key.
    It also generates random AES key, using SHA3-512(hashes of enrypted files and a random number) and encrypts it using RSA public key.
    Using the password and encrypted private key, it decrypts firstly the private key and then it uses it to decrypt the AES key.
    */
    class KeyEncryptionTool   {
        public:
            void set_rsa_keys(  const boost::multiprecision::cpp_int &pq,
                                const boost::multiprecision::cpp_int &public_key,
                                const boost::multiprecision::cpp_int &private_key_xor_password_hash,
                                unsigned int rsa_key_size);

            /* Take the input string, add hex representation of random number to it and calculate SHA-256 */
            boost::multiprecision::cpp_int generate_aes_key(const std::string &file_hashes_summary) const;

            /* Encrypt AES key using RSA public key */
            boost::multiprecision::cpp_int encrypt_aes_key(const boost::multiprecision::cpp_int &aes_key) const;

            /* Encrypt AES key using encrypted RSA private key and the password */
            boost::multiprecision::cpp_int decrypt_aes_key(const boost::multiprecision::cpp_int &aes_key_encrypted, const std::string &password) const;

            /* Returns string with the summary of all keys and necessary info: RSA_lenght, RSA_pq, RSA_pub_key, RSA_envrypted_priv_key, encypted_AES key */
            std::string produce_key_summary_string(const boost::multiprecision::cpp_int &aes_key)    const;

            /* Take string produced by produce_key_summary_string method and load the keys. If password is non-empty string, it will decode the encrypted keys */
            void load_key_summary_string(const std::string key_summary_string, const std::string &password);

            /* XOR private key and the hash of the password */
            static boost::multiprecision::cpp_int  encrypt_private_key( const boost::multiprecision::cpp_int &private_key,
                                                                        const std::string &password, unsigned int rsa_type);

            static boost::multiprecision::cpp_int  decrypt_private_key( const boost::multiprecision::cpp_int &private_key_encrypted,
                                                                        const std::string &password, unsigned int rsa_type);


            /* Calculate pseudo-random number using SHA3-512 with the bith length equal to rsa_key_length */
            static boost::multiprecision::cpp_int  generate_rsa_bit_length_size_password_hash(  const std::string &password,
                                                                                                unsigned int rsa_key_length);

            boost::multiprecision::cpp_int  get_rsa_pq()                        const   {return m_pq;};
            boost::multiprecision::cpp_int  get_rsa_public_key()                const   {return m_public_key;};
            boost::multiprecision::cpp_int  get_rsa_private_key()               const   {return m_private_key;};
            boost::multiprecision::cpp_int  get_rsa_private_key_encrypted()     const   {return m_private_key_xor_password_hash;};
            int                             get_rsa_key_length()                const   {return m_rsa_key_size;};
            boost::multiprecision::cpp_int  get_aes_key()                       const   {return m_aes_key;};
            boost::multiprecision::cpp_int  get_aes_key_encrypted()             const   {return m_aes_key_encrypted;};

        private:
            boost::multiprecision::cpp_int  m_pq;
            boost::multiprecision::cpp_int  m_public_key;
            boost::multiprecision::cpp_int  m_private_key_xor_password_hash;
            boost::multiprecision::cpp_int  m_private_key = -1;
            unsigned int                    m_rsa_key_size;

            boost::multiprecision::cpp_int  m_aes_key_encrypted = -1;
            boost::multiprecision::cpp_int  m_aes_key           = -1;


    };
}