#include "../EncryptedBackuper/KeyFileHandler.h"

#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"
#include "../EncryptedBackuper/KeyEncryptionTool.h"

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
    const vector<string> lines_of_key_file = read_lines_of_text_file(key_file, 10);
    if (lines_of_key_file.size() != 4) {
        throw std::string("Unable to read key file: " + key_file);
    }
    m_rsa_type      = std::stoi(lines_of_key_file[0]);

    m_pq            = cpp_int(lines_of_key_file[1]);
    m_public_key    = cpp_int(lines_of_key_file[2]);
    m_private_key_encrypted = cpp_int(lines_of_key_file[3]);
    m_private_key   = KeyEncryptionTool::decrypt_private_key(cpp_int(lines_of_key_file[3]), password, m_rsa_type);

};

void KeyFileHandler::save_keys_to_file(const std::string &key_file, const std::string &password)    {
    const cpp_int password_hash_plus_private_key   = KeyEncryptionTool::encrypt_private_key(m_private_key, password, m_rsa_type);

    ofstream outfile;
    outfile.open(key_file);
    outfile << m_rsa_type << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(m_pq) << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(m_public_key) << endl;
    outfile << "0x" + convert_cpp_int_to_hex_string(password_hash_plus_private_key) << endl;
    outfile.close();

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