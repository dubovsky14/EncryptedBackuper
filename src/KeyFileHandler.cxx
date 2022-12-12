#include "../EncryptedBackuper/KeyFileHandler.h"

#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <fstream>
#include <vector>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;


void KeyFileHandler::generate_keys(unsigned int rsa_key_length) {
    if (!valid_rsa_type(rsa_key_length))    {
        throw std::string("Invalid RSA key length! Only multiples of 512 are allowed!");
    };

    m_rsa_type = rsa_key_length;
    bool valid_key = false;
    while (!valid_key) {
        valid_key = generate_rsa_keys(&m_pq, &m_private_key, m_public_key, rsa_key_length);
    }
};

void KeyFileHandler::load_keys_from_file(const std::string &key_file, const std::string &password)  {
    vector<string> lines_of_key_file = read_lines_of_text_file(key_file, 10);
    if (lines_of_key_file.size() != 4) {
        throw std::string("Unable to read key file: " + key_file);
    }
    m_rsa_type      = std::stoi(lines_of_key_file[0]);

    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, m_rsa_type);

    m_pq            = cpp_int(lines_of_key_file[1]);
    m_public_key    = cpp_int(lines_of_key_file[2]);
    m_private_key   = cpp_int(lines_of_key_file[3]) ^ password_extended_hash;

};

void KeyFileHandler::save_keys_to_file(const std::string &key_file, const std::string &password)    {
    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, m_rsa_type);
    cpp_int password_hash_plus_private_key = m_private_key ^ password_extended_hash;

    ofstream outfile;
    outfile.open(key_file);
    outfile << m_rsa_type << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(m_pq) << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(m_public_key) << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(password_hash_plus_private_key) << endl;
    outfile.close();

};


boost::multiprecision::cpp_int  KeyFileHandler::generate_rsa_bit_length_size_password_hash( const std::string &password,
                                                                                            unsigned int rsa_key_length)    {

    const unsigned int sha3_type = 512;
    SHA3Calculator password_hasher(sha3_type);
    password_hasher.hash_message(password);
    cpp_int password_extended_hash = password_hasher.get_hash();
    const unsigned int required_number_of_hashes = rsa_key_length/sha3_type;
    const cpp_int bitshift_constant = square_and_multiply(cpp_int(2), sha3_type, 0);
    for (unsigned int i = 1; i<required_number_of_hashes; i++)   {
        password_extended_hash *= bitshift_constant;
        password_extended_hash += password_hasher.apply_next_keccak_and_get_output();
    }
    return password_extended_hash;
};


std::vector<std::string> KeyFileHandler::read_lines_of_text_file(const std::string &input_file, unsigned max_number_of_lines)   {
    string line;
    vector<string> result;
    ifstream ifile (input_file);
    if (ifile.is_open())    {
        while ( getline (ifile,line) )        {
            result.push_back(line);
            if (result.size() >= max_number_of_lines && max_number_of_lines != 0)   {
                break;
            }
        }
        ifile.close();
    }
    else    {
        throw std::string("Unable to open file \"" + input_file + "\"");
    }
    return result;
};

bool KeyFileHandler::valid_rsa_type(unsigned int rsa_key_length)    {
    if      (rsa_key_length == 0)     return false;
    return   (rsa_key_length % 512) == 0;
};