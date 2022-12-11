#include "../EncryptedBackuper/SHA3_message_parser.h"

using namespace EncryptedBackuper;
using namespace std;

SHA3_message_parser::SHA3_message_parser(const std::string &input, SHA3_input_type input_type, unsigned int block_size_bits)  {
    set_output_block_size(block_size_bits);
    if  (input_type == SHA3_input_type::enum_file)   {
        m_input_file = make_shared<ifstream>(input, std::ios::binary | std::ios::in);
        m_unpadded_input_length_bits = get_file_size(input);
    }
    else if (input_type == SHA3_input_type::enum_string)   {
        m_input_string = make_shared<string>(input);
        m_unpadded_input_length_bits = 8*input.length();
    }
    initialize_padding_length();
};

SHA3_message_parser::SHA3_message_parser(const boost::multiprecision::cpp_int &input, unsigned int block_size_bits)   {
    set_output_block_size(block_size_bits);
    m_input_cpp_int = make_shared<boost::multiprecision::cpp_int>(input);
    m_unpadded_input_length_bits = msb(input);
};

bool SHA3_message_parser::get_block(unsigned int *output)   {
    if (m_current_block_index == m_number_of_blocks)    {
        return false;
    }
    const int output_length_bytes = m_output_length_bits/8;

    if (m_input_string) {

        // blocks that do not contain any padding, we just need to copy the data
        if (m_current_block_index < m_number_of_blocks_wo_padding_bits) {
            memcpy(output, &((*m_input_string)[output_length_bytes*m_current_block_index]), output_length_bytes);
        }
        // the last block of the original data can be either only data, or data+padding
        else if (m_current_block_index == m_number_of_blocks_wo_padding_bits)    {
            const short int number_of_original_bytes = (m_unpadded_input_length_bits % m_output_length_bits)/8;

            // copy the remaining bytes of the original data
            memcpy(output, &((*m_input_string)[output_length_bytes*m_current_block_index]), number_of_original_bytes);

            // the block contain both data and padding
            if (number_of_original_bytes != output_length_bytes) {
                unsigned char *output_bytes = reinterpret_cast<unsigned char *>(output);

                // if padding is one byte only
                if (m_padding_length == 8)  {
                    output_bytes[output_length_bytes-1] = 0b10000110;
                }
                else {
                    output_bytes[number_of_original_bytes] = 0b00000110;
                    for (int i_byte = number_of_original_bytes+1; i_byte < output_length_bytes-1; i_byte++)   {
                        output_bytes[i_byte] = 0;
                    }
                    output_bytes[output_length_bytes-1] = 0b10000000;
                }
            }
        }
        // in this case the last block contains only the padding
        else if (m_current_block_index == m_number_of_blocks_wo_padding_bits+1)    {
            unsigned char *output_bytes = reinterpret_cast<unsigned char *>(output);

            output_bytes[0] = 0b00000110;
            for (int i_byte = 1; i_byte < output_length_bytes-1; i_byte++)   {
                output_bytes[i_byte] = 0;
            }
            output_bytes[output_length_bytes-1] = 0b10000000;
        }
    }

    m_current_block_index++;
    return true;
};

uint64_t SHA3_message_parser::get_file_size(const std::string &file_address) {
    ifstream file(file_address, ios::binary);
    const auto begin = file.tellg();
    file.seekg (0, ios::end);
    const auto end = file.tellg();
    file.close();
    return (end-begin);
};

void SHA3_message_parser::initialize_padding_length()  {
    m_number_of_blocks = (m_unpadded_input_length_bits+m_output_length_bits-1)/m_output_length_bits;
    m_number_of_blocks_wo_padding_bits = m_unpadded_input_length_bits % m_output_length_bits ? m_number_of_blocks-1 : m_number_of_blocks;

    m_padding_length = m_number_of_blocks*m_output_length_bits - m_unpadded_input_length_bits;
    if (m_padding_length < 4)   {
        m_padding_length += m_output_length_bits;
        m_number_of_blocks++;
    }
};

void SHA3_message_parser::set_output_block_size(unsigned int block_size_bits)   {
    if (block_size_bits == 1152)        m_output_length_bits = block_size_bits; // SHA3-224
    else if (block_size_bits == 1088)   m_output_length_bits = block_size_bits; // SHA3-256
    else if (block_size_bits == 832)    m_output_length_bits = block_size_bits; // SHA3-384
    else if (block_size_bits == 576)    m_output_length_bits = block_size_bits; // SHA3-512
    else {
        throw std::string("SHA3_message_parser::set_output_block_size: Unknown output bit size");
    }
};