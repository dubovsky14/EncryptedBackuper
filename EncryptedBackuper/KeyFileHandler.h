#pragma once

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <vector>


namespace EncryptedBackuper     {
    class KeyFileHandler    {
        public:
            void generate_keys(unsigned int rsa_key_length);

            void load_keys_from_file(const std::string &key_file, const std::string &password);

            void save_keys_to_file(const std::string &key_file, const std::string &password);

            boost::multiprecision::cpp_int  get_public_key()    const   {return m_public_key;};

            boost::multiprecision::cpp_int  get_private_key()   const   {return m_private_key;};

            boost::multiprecision::cpp_int  get_pq()            const   {return m_pq;};

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