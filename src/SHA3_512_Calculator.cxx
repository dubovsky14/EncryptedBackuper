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

void SHA3_512_Calculator::keccak_f_function()   {
    for (unsigned int i_round = 0; i_round < 24; i_round++) {
        theta();
        rho_and_pi();
        chi();
        iota(i_round);
    }
};

void SHA3_512_Calculator::theta()   {
    for (int i_x = 0; i_x < 5; i_x++)   {
        unsigned int sum_x_minus_one    = 0;    // XOR between all columns in (i_x-1) line
        unsigned int i_x_minus_one      = SHA3_512_Calculator::mod(i_x-1, 5);
        unsigned int rot_sum_x_plus_one = 0;    // XOR between all columns in (i_x+1) line with circular shift of -1 bit
        unsigned int i_x_plus_one       = SHA3_512_Calculator::mod(i_x+1, 5);

        // calculate sum of the previous and next "layers" in x direction
        for (int i_y = 0; i_y < 5; i_y++)   {
            sum_x_minus_one     = sum_x_minus_one    ^ m_state[i_x_minus_one][i_y];
            rot_sum_x_plus_one  = rot_sum_x_plus_one ^ m_state[i_x_plus_one] [i_y];
        }

        // rotate rot_sum_x_plus_one by one bit
        rot_sum_x_plus_one = SHA3_512_Calculator::circular_bit_shift(rot_sum_x_plus_one, -1);

        // calculate sum of the previous and next "layers" in x direction
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_x][i_y]     = m_state[i_x][i_y] ^ rot_sum_x_plus_one ^ sum_x_minus_one;
        }
    }
};

void SHA3_512_Calculator::rho_and_pi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_B_array[i_y][mod(2*i_x + 3*i_y, 5)] = SHA3_512_Calculator::circular_bit_shift(m_state[i_x][i_y], s_rotation_offsets[i_x][i_y]);
        }
    }
};

void SHA3_512_Calculator::chi() {
    for (int i_x = 0; i_x < 5; i_x++)   {
        for (int i_y = 0; i_y < 5; i_y++)   {
            m_state[i_x][i_y] = m_B_array[i_x][i_y] ^ ((~m_B_array[(i_x+1) % 5][i_y]) & m_B_array[(i_x+2) % 5][i_y]);
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
    unsigned int message[19];
    while(m_message_parser->get_block(message)) {

    }
};

cpp_int EncryptedBackuper::SHA3_512(const std::string &message);

cpp_int EncryptedBackuper::SHA3_512_from_file(const std::string &input_file);

cpp_int EncryptedBackuper::SHA3_512(const cpp_int &message);
