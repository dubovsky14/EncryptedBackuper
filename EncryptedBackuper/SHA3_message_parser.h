#pragma once

#include <string>
#include <fstream>
#include <memory>

#include <boost/multiprecision/cpp_int.hpp>

namespace EncryptedBackuper {

    enum class SHA3_input_type{enum_file, enum_string};

    class SHA3_message_parser   {
        public:
            /* Either open input file at "input" address or process input as a message, depending on input type*/
            SHA3_message_parser(const std::string &input, SHA3_input_type input_type, unsigned int block_size_bits = 576);

            /* Parse cpp_int*/
            SHA3_message_parser(const boost::multiprecision::cpp_int &input, unsigned int block_size_bits = 576);

            /* Read block of 576 bits (72 bytes = 9 unsigned integers). Return false if there is no more the message to be parsed. */
            bool get_block(unsigned int *output);

            unsigned int get_block_size_bits()   const   {return m_output_length_bits;};

        private:
            std::shared_ptr<boost::multiprecision::cpp_int> m_input_cpp_int = nullptr;
            std::shared_ptr<std::string>                    m_input_string  = nullptr;
            std::shared_ptr<std::ifstream>                  m_input_file    = nullptr;

            unsigned long long int      m_unpadded_input_length_bits        = 0;
            unsigned long long int      m_number_of_blocks                  = 0;
            unsigned long long int      m_number_of_blocks_wo_padding_bits  = 0;
            unsigned long long int      m_current_block_index               = 0;



            static uint64_t get_file_size(const std::string &file_address);

            void                        initialize_padding_length();
            unsigned int                m_padding_length = 0;

            void                        set_output_block_size(unsigned int block_size_bits);
            unsigned int                m_output_length_bits = 576;

    };
}