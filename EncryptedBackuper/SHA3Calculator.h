#pragma once

#include "../EncryptedBackuper/SHA3_message_parser.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <memory>

#include <string>

namespace EncryptedBackuper {
    class SHA3Calculator   {
        public:
            SHA3Calculator()   = delete;

            /* output size = 512 for SHA3-512, 256 for SHA3-256 etc. */
            SHA3Calculator(unsigned int output_size);

            void reset_state();

            void  hash_file(const std::string &input_file);

            void  hash_message(const std::string &message);

            boost::multiprecision::cpp_int get_hash();

        private:
            unsigned long long int  m_state[5][5];
            unsigned long long int  m_B_array[5][5]; // array calculated by rho and phi steps


            std::shared_ptr<SHA3_message_parser>    m_message_parser   = nullptr;

            void keccak_f_function();

            void theta();
            void rho_and_pi();
            void chi();
            void iota(unsigned int i_round);

            static unsigned int mod(int number, int modulo);

            void iterate_over_message();

            unsigned int            m_output_size_bits;
            unsigned int            m_input_block_size_bits;
            void                    set_number_of_output_bits(unsigned int number_of_output_bits);  // 512 = SHA3-512, 256 = SHA3-256, etc.

            template<typename InputType>
            static InputType circular_bit_shift(InputType input, unsigned int shift_size)   {
                unsigned int input_size = 8*sizeof(input);
                shift_size = mod(shift_size, input_size);
                return (InputType)(InputType)(input << shift_size) | (InputType)(input >> mod(input_size - shift_size, input_size));
            };

            static constexpr unsigned int s_rotation_offsets[5][5]    =   {
                {0,36,3,105,210},
                {1,300,10,45,66},
                {190,6,171,15,253},
                {28,55,153,21,120},
                {91,276,231,136,78},
            };

            static constexpr unsigned long long int s_round_constants[24]    =   {
                0x0000000000000001,
                0x0000000000008082,
                0x800000000000808A,
                0x8000000080008000,
                0x000000000000808B,
                0x0000000080000001,
                0x8000000080008081,
                0x8000000000008009,
                0x000000000000008A,
                0x0000000000000088,
                0x0000000080008009,
                0x000000008000000A,
                0x000000008000808B,
                0x800000000000008B,
                0x8000000000008089,
                0x8000000000008003,
                0x8000000000008002,
                0x8000000000000080,
                0x000000000000800A,
                0x800000008000000A,
                0x8000000080008081,
                0x8000000000008080,
                0x0000000080000001,
                0x8000000080008008,
            };
    };

    unsigned long long int get_bit_length(const boost::multiprecision::cpp_int &number);
}