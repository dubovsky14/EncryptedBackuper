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


        private:
            unsigned long long int  m_state[5][5];

            void keccak_f_function();

            void theta();
            void rho();
            void pi();
            void chi();
            void iota();

            static unsigned int mod(int number, int modulo);

            template<typename InputType>
            static InputType circular_bit_shift(InputType input, unsigned int shift_size)   {
                unsigned int input_size = 8*sizeof(input);
                shift_size = mod(shift_size, input_size);
                return (InputType)(InputType)(input << shift_size) | (InputType)(input >> mod(input_size - shift_size, input_size));
            };

            static constexpr unsigned int s_rotation_constants[5][5]    =   {
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