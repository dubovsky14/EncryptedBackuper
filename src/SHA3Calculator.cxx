#include "../EncryptedBackuper/SHA3Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>

using namespace std;
using namespace EncryptedBackuper;
using boost::multiprecision::cpp_int;

SHA3Calculator::SHA3Calculator(unsigned int output_size)  {
    reset_state();
    set_number_of_output_bits(output_size);
};

void SHA3Calculator::reset_state() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_x][i_y] = 0;
        }
    }
};

void  SHA3Calculator::hash_file(const std::string &input_file)  {
    m_message_parser = make_shared<SHA3_message_parser>(input_file, EncryptedBackuper::SHA3_input_type::enum_file, m_input_block_size_bits);
    iterate_over_message();
};

void  SHA3Calculator::hash_message(const std::string &message)  {
    m_message_parser = make_shared<SHA3_message_parser>(message, EncryptedBackuper::SHA3_input_type::enum_string, m_input_block_size_bits);
    iterate_over_message();
};

boost::multiprecision::cpp_int SHA3Calculator::get_hash()   {
    cpp_int result = 0;

    const unsigned long long *state = reinterpret_cast<const unsigned long long *>(m_state);
    unsigned int current_output_size = 0;

    for (unsigned int i_word = 0; i_word < 8; i_word++)   {
        unsigned char bytes[8];
        memcpy(bytes, &state[i_word], 8);
        for (int i_byte = 0; i_byte < 8; i_byte++)   {
            result *= 256;
            result += bytes[i_byte];
            current_output_size += 8;
            if (current_output_size >= m_output_size_bits)  return result;
        }
    }
    return result;
};

boost::multiprecision::cpp_int SHA3Calculator::apply_next_keccak_and_get_output()  {
    keccak_f_function();
    return get_hash();
}

void SHA3Calculator::keccak_f_function()   {
    for (unsigned int i_round = 0; i_round < 24; i_round++) {
        theta();
        rho_and_pi();
        chi();
        iota(i_round);
    }
};

void SHA3Calculator::theta()   {
    unsigned long long int C[5];
    unsigned long long int D[5];

    for (int i_x = 0; i_x < 5; i_x++)   {
        C[i_x]  = m_state[0][(i_x + 4) % 5];
        D[i_x]  = m_state[0][(i_x + 1) % 5];

        // calculate sum of the previous and next "layers" in x direction
        for (int i_y = 1; i_y < 5; i_y++)   {
            C[i_x]  = C[i_x] ^ m_state[i_y][(i_x + 4) % 5];
            D[i_x]  = D[i_x] ^ m_state[i_y][(i_x + 1) % 5];
        }

        // rotate rot_sum_x_plus_one by one bit
        D[i_x] = SHA3Calculator::circular_bit_shift(D[i_x], 1);
    }
    for (int i_x = 0; i_x < 5; i_x++)   {
        // calculate sum of the previous and next "layers" in x direction
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_y][i_x]     = m_state[i_y][i_x] ^ D[i_x] ^ C[i_x];
        }
    }
};

void SHA3Calculator::rho_and_pi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_B_array[mod(2*i_x + 3*i_y, 5)][i_y] = SHA3Calculator::circular_bit_shift(m_state[i_y][i_x], s_rotation_offsets[i_x][i_y]);
        }
    }
};

void SHA3Calculator::chi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_y][i_x] = m_B_array[i_y][i_x] ^ ((~m_B_array[i_y][(i_x+1) % 5]) & m_B_array[i_y][(i_x+2) % 5]);
        }
    }
};

void SHA3Calculator::iota(unsigned int i_round)    {
    m_state[0][0] = m_state[0][0] ^ s_round_constants[i_round];
};

unsigned int SHA3Calculator::mod(int number, int modulo)   {
    int result = number % modulo;
    if (result < 0)  {
        result += modulo;
    }
    return result;
};

void SHA3Calculator::iterate_over_message()    {
    const unsigned int input_block_size_in_uint32s = m_input_block_size_bits/32;
    unsigned int message[input_block_size_in_uint32s];
    unsigned int *state_as_32bit_uints = reinterpret_cast<unsigned int* >(m_state);

    while(m_message_parser->get_block(message)) {
        for (unsigned int i = 0; i < input_block_size_in_uint32s; i++)   {
            state_as_32bit_uints[i] = state_as_32bit_uints[i] ^ message[i];
        }
        keccak_f_function();
    }
};

void SHA3Calculator::set_number_of_output_bits(unsigned int number_of_output_bits) {
    if (number_of_output_bits == 224)   {
        m_output_size_bits      = 224;
        m_input_block_size_bits = 1152;
    }
    else if (number_of_output_bits == 256)   {
        m_output_size_bits      = 256;
        m_input_block_size_bits = 1088;
    }
    else if (number_of_output_bits == 384)   {
        m_output_size_bits      = 384;
        m_input_block_size_bits = 832;
    }
    else if (number_of_output_bits == 512)   {
        m_output_size_bits      = 512;
        m_input_block_size_bits = 576;
    }
    else {
        throw std::string("Unknown SHA3 bit length: " + std::to_string(number_of_output_bits));
    }
};


boost::multiprecision::cpp_int EncryptedBackuper::calculate_sha3(const string &message, unsigned int sha3_type) {
    SHA3Calculator password_hasher(sha3_type);
    password_hasher.hash_message(message);
    return password_hasher.get_hash();
};

boost::multiprecision::cpp_int EncryptedBackuper::calculate_sha3_from_file(const std::string &file, unsigned int sha3_type) {
    SHA3Calculator password_hasher(sha3_type);
    password_hasher.hash_file(file);
    return password_hasher.get_hash();
};