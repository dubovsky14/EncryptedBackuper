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

    m_padding_length = m_number_of_blocks*s_output_length_bits - m_unpadded_input_length_bits;
    if (m_padding_length < 4)   {
        m_padding_length += s_output_length_bits;
        m_number_of_blocks++;
    }
};