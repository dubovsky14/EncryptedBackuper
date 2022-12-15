
#include "../EncryptedBackuper/BinaryDecryptor.h"

#include "../EncryptedBackuper/StringOperations.h"
#include "../EncryptedBackuper/RSA_related_math_functions.h"

using namespace std;
using namespace EncryptedBackuper;

BinaryDecryptor::BinaryDecryptor(const std::string &encrypted_file_address) {
    m_encrypted_file_address = encrypted_file_address;
};

void BinaryDecryptor::decrypt_files(const std::string &decrypted_files_folder, const std::string &password) {
    m_input_binary = make_shared<ifstream>(m_encrypted_file_address, std::ios::binary | std::ios::in);
    load_keys(password);
    read_list_of_files();
    print_out_filelist();
    decrypt_files();
};

void BinaryDecryptor::load_keys(const std::string &password)   {
    // load key string from the binary
    string key_string;
    char x;
    while(m_input_binary->good())    {
        (*m_input_binary)  >> std::noskipws >> x;
        if (x == '|')       {
            break;
        }
        key_string = key_string + x;
    }

    // parse key string and decrypt private key
    m_key_encryption_tool->load_key_summary_string(key_string, password);

    // check if the decrypted private key is valid (i.e. password was correct)
    const bool keys_are_valid = m_key_encryption_tool->validate_keys();
    if (!keys_are_valid)    {
        throw std::string("Invalid password!");
    }

    m_aes_key = m_key_encryption_tool->get_aes_key();
    m_aes_wrapper = std::make_shared<AESWrapper>(m_aes_key, 256);
};

void BinaryDecryptor::read_list_of_files()  {
    const string filelist_string = read_filelist_string();
    m_file_list_handler->load_filelist_from_string(filelist_string);
};

string BinaryDecryptor::read_filelist_string()  {
    string result;
    string one_aes_block = "0123456789abcdef"; // I just need a 16 chars long buffer

    const string filelist_termination_string = "/*FILELIST_END*/";
    unsigned char input_buffer[16];
    while(m_input_binary->good())    {
        (*m_input_binary)   >> std::noskipws
                            >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                            >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        m_aes_wrapper->decrypt(input_buffer);
        for (unsigned int i_char = 0; i_char < 16; i_char++)    {
            one_aes_block[i_char] = char(input_buffer[i_char]);
        }
        if (one_aes_block == filelist_termination_string)   {
            return result;
        }
        result = result + one_aes_block;
    }
    return result;
};

void BinaryDecryptor::decrypt_files()   {

};

void BinaryDecryptor::print_out_keys()  const {
    cout << "RSA type = " << m_key_encryption_tool->get_rsa_key_length() << endl;
    cout << "pq = 0x" << convert_cpp_int_to_hex_string(m_key_encryption_tool->get_rsa_pq()) << endl;
    cout << "public_key = 0x" << convert_cpp_int_to_hex_string(m_key_encryption_tool->get_rsa_public_key()) << endl;
    cout << "private_key = 0x" << convert_cpp_int_to_hex_string(m_key_encryption_tool->get_rsa_private_key()) << endl;
    cout << "AES key = 0x" << convert_cpp_int_to_hex_string(m_key_encryption_tool->get_aes_key()) << endl;
};

void BinaryDecryptor::print_out_filelist()  const {
    const vector<string> file_names           = m_file_list_handler->get_list_of_files_names_only();
    const vector<long long int> file_sizes    = m_file_list_handler->get_files_sizes();

    for (unsigned int i_file = 0; i_file < file_names.size(); i_file++) {
        cout << file_names[i_file] << "\t\t" << file_sizes[i_file] << endl;
    }
};