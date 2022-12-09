#pragma once

#include <boost/multiprecision/cpp_int.hpp>

#include <string>

namespace EncryptedBackuper {
    class SHA3_512_Calculator   {
        public:
            SHA3_512_Calculator();

            void reset_state();

            void  hash_gile(const std::string &input_file);

            void  hash_message(const std::string &message);

            void  hash_message(const boost::multiprecision::cpp_int &message);

            boost::multiprecision::cpp_int get_hash();

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

        private:
            unsigned long long int  m_state[5][5];
            unsigned long long int  m_B_array[5][5]; // array calculated by rho and phi steps

            void keccak_f_function();

            void theta();
            void rho_and_pi();
            void chi();
            void iota(unsigned int i_round);

            static unsigned int mod(int number, int modulo);

            template<typename InputType>
            static InputType circular_bit_shift(InputType input, unsigned int shift_size)   {
                unsigned int input_size = 8*sizeof(input);
                shift_size = mod(shift_size, input_size);
                return (InputType)(InputType)(input << shift_size) | (InputType)(input >> mod(input_size - shift_size, input_size));
            };

            static constexpr unsigned int s_rotation_offsets[5][5]    =   {
                {0,36,3,41,18},
                {1,44,10,45,2},
                {62,6,43,15,61},
                {28,55,25,21,56},
                {27,20,39,8,14},
            };

    };


    boost::multiprecision::cpp_int SHA3_512(const std::string &message);

    boost::multiprecision::cpp_int SHA3_512_from_file(const std::string &input_file);

    boost::multiprecision::cpp_int SHA3_512(const boost::multiprecision::cpp_int &message);


    unsigned long long int get_bit_length(const boost::multiprecision::cpp_int &number);
}