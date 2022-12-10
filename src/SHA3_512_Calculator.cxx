#include "../EncryptedBackuper/SHA3_512_Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>

using namespace std;
using namespace EncryptedBackuper;
using boost::multiprecision::cpp_int;

SHA3_512_Calculator::SHA3_512_Calculator()  {
    reset_state();
};

void SHA3_512_Calculator::reset_state() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_x][i_y] = 0;
        }
    }
};

void  SHA3_512_Calculator::hash_file(const std::string &input_file)  {
    m_message_parser = make_shared<SHA3_message_parser>(input_file, EncryptedBackuper::SHA3_input_type::enum_file);
    iterate_over_message();
};

void  SHA3_512_Calculator::hash_message(const std::string &message)  {
    m_message_parser = make_shared<SHA3_message_parser>(message, EncryptedBackuper::SHA3_input_type::enum_string);
    iterate_over_message();
};

void  SHA3_512_Calculator::hash_message(const boost::multiprecision::cpp_int &message)   {
    m_message_parser = make_shared<SHA3_message_parser>(message);
    iterate_over_message();
};

boost::multiprecision::cpp_int SHA3_512_Calculator::get_hash()   {
    const cpp_int two_to_64 = cpp_int("0x10000000000000000");
    cpp_int result = 0;

    const unsigned long long *state = reinterpret_cast<const unsigned long long *>(m_state);

    for (unsigned int i_word = 0; i_word < 8; i_word++)   {
        unsigned char bytes[8];
        memcpy(bytes, &state[i_word], 8);
        for (int i_byte = 0; i_byte < 8; i_byte++)   {
            result *= 256;
            result += bytes[i_byte];
        }
    }
    return result;
};

void SHA3_512_Calculator::keccak_f_function()   {
    for (unsigned int i_round = 0; i_round < 24; i_round++) {
        theta();
        rho_and_pi();
        chi();
        iota(i_round);
    }
};

void SHA3_512_Calculator::theta()   {
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
        D[i_x] = SHA3_512_Calculator::circular_bit_shift(D[i_x], 1);
    }
    for (int i_x = 0; i_x < 5; i_x++)   {
        // calculate sum of the previous and next "layers" in x direction
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_y][i_x]     = m_state[i_y][i_x] ^ D[i_x] ^ C[i_x];
        }
    }
};

void SHA3_512_Calculator::rho_and_pi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_B_array[mod(2*i_x + 3*i_y, 5)][i_y] = SHA3_512_Calculator::circular_bit_shift(m_state[i_y][i_x], s_rotation_offsets[i_x][i_y]);
        }
    }
};

void SHA3_512_Calculator::chi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_y][i_x] = m_B_array[i_y][i_x] ^ ((~m_B_array[i_y][(i_x+1) % 5]) & m_B_array[i_y][(i_x+2) % 5]);
        }
    }
};

void SHA3_512_Calculator::iota(unsigned int i_round)    {
    m_state[0][0] = m_state[0][0] ^ s_round_constants[i_round];
};

unsigned int SHA3_512_Calculator::mod(int number, int modulo)   {
    int result = number % modulo;
    if (result < 0)  {
        result += modulo;
    }
    return result;
};

void SHA3_512_Calculator::iterate_over_message()    {
    unsigned int message[18];
    unsigned int *state_as_32bit_uints = reinterpret_cast<unsigned int* >(m_state);

    while(m_message_parser->get_block(message)) {
        for (unsigned int i = 0; i < 18; i++)   {
            state_as_32bit_uints[i] = state_as_32bit_uints[i] ^ message[i];
        }
        keccak_f_function();
    }
};


cpp_int EncryptedBackuper::SHA3_512(const std::string &message);

cpp_int EncryptedBackuper::SHA3_512_from_file(const std::string &input_file);

cpp_int EncryptedBackuper::SHA3_512(const cpp_int &message);
