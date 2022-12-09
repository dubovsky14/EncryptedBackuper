#include "../EncryptedBackuper/SHA3_message_parser.h"

using namespace EncryptedBackuper;
using namespace std;

SHA3_message_parser::SHA3_message_parser(const std::string &input, SHA3_input_type input_type)  {
    if  (input_type == SHA3_input_type::enum_file)   {
        m_input_file = make_shared<ifstream>(input, std::ios::binary | std::ios::in);
        m_unpadded_input_length_bits = get_file_size(input);
    }
    else if (input_type == SHA3_input_type::enum_string)   {
        m_input_string = make_shared<string>(input);
        m_unpadded_input_length_bits = 8*input.length();
    }
};

SHA3_message_parser::SHA3_message_parser(const boost::multiprecision::cpp_int &input)   {
    m_input_cpp_int = make_shared<boost::multiprecision::cpp_int>(input);
    m_unpadded_input_length_bits = msb(input);
};

bool SHA3_message_parser::get_block(unsigned int *output)   {
    if (m_input_string) {

        // blocks that do not contain any padding, we just need to copy the data
        if (m_current_block_index < m_number_of_blocks_wo_padding_bits) {
            memcpy(output, &((*m_input_string)[72*m_current_block_index]), 19);
        }
        // the last block of the original data can be either only data, or data+padding
        else if (m_current_block_index == m_number_of_blocks_wo_padding_bits)    {
            const short int number_of_original_bytes = (m_unpadded_input_length_bits % s_output_length_bits)/8;

            // copy the remaining bytes of the original data
            memcpy(output, &((*m_input_string)[72*m_current_block_index]), number_of_original_bytes);

            // the block contain both data and padding
            if (number_of_original_bytes != 72) {
                unsigned char *output_bytes = reinterpret_cast<unsigned char *>(output);

                // if padding is one byte only
                if (m_padding_length == 8)  {
                    output_bytes[71] = 0b01100001;
                }
                else {
                    output_bytes[number_of_original_bytes] = 0b01100000;
                    for (unsigned i_byte = number_of_original_bytes+1; i_byte < 71; i_byte)   {
                        output_bytes[i_byte] = 0;
                    }
                    output_bytes[71] = 0b00000001;
                }
            }
        }
        // in this case the last block contains only the padding
        else if (m_current_block_index == m_number_of_blocks_wo_padding_bits+1)    {
            const short int number_of_original_bytes = (m_unpadded_input_length_bits % s_output_length_bits)/8;
            unsigned char *output_bytes = reinterpret_cast<unsigned char *>(output);

            output_bytes[0] = 0b01100000;
            for (unsigned i_byte = number_of_original_bytes+1; i_byte < 71; i_byte)   {
                output_bytes[i_byte] = 0;
            }
            output_bytes[71] = 0b00000001;
        }
    }

    m_current_block_index++;
    return (m_number_of_blocks != m_current_block_index);
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
    m_number_of_blocks = (m_unpadded_input_length_bits+s_output_length_bits-1)/s_output_length_bits;
    m_number_of_blocks_wo_padding_bits = m_unpadded_input_length_bits % s_output_length_bits ? m_number_of_blocks-1 : m_number_of_blocks;

    m_padding_length = m_number_of_blocks*s_output_length_bits - m_unpadded_input_length_bits;
    if (m_padding_length < 4)   {
        m_padding_length += s_output_length_bits;
        m_number_of_blocks++;
    }
};