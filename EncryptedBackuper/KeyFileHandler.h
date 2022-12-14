#pragma once

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <vector>


namespace EncryptedBackuper     {

    /* Class responsible for generating and handling RSA keys. It generates pq, public and private keys.
    Then it encrypts the private key and is able to dump it to a text file.
    It can leter read this text file and load public key and pq. If password is provided it can decrypt and load also private key.
    */
    class KeyFileHandler    {
        public:
            /* Generate RSA public and private key and pq */
            void generate_keys(unsigned int rsa_key_length);

            /* Load RSA keys from file. Password is necessary to decrypt private key */
            void load_keys_from_file(const std::string &key_file, const std::string &password);

            /* Dump RSA keys to file. Password is necessary to encrypt the private key */
            void save_keys_to_file(const std::string &key_file, const std::string &password);

            boost::multiprecision::cpp_int  get_public_key()    const   {return m_public_key;};

            boost::multiprecision::cpp_int  get_private_key()   const   {return m_private_key;};

            boost::multiprecision::cpp_int  get_pq()            const   {return m_pq;};

            /* Lenght of the key in bites, i.e. 1024, 2048, 4096 etc. */
            unsigned int                    get_rsa_type()      const   {return m_rsa_type;};

    private:
            unsigned int                    m_rsa_type      = 0;
            boost::multiprecision::cpp_int  m_pq            = 0;
            boost::multiprecision::cpp_int  m_public_key    = 65537;
            boost::multiprecision::cpp_int  m_private_key   = 0;

            static std::vector<std::string> read_lines_of_text_file(const std::string &input_file, unsigned max_number_of_lines = 0);

            static bool valid_rsa_type(unsigned int rsa_key_length);
    };
}