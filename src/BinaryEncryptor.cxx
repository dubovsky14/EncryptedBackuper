#include "../EncryptedBackuper/BinaryEncryptor.h"
#include "../EncryptedBackuper/BinaryFileFunctions.h"

using namespace EncryptedBackuper;
using namespace std;
using AES::AESHandler;
using boost::multiprecision::cpp_int;

BinaryEncryptor::BinaryEncryptor(   const std::string &key_file,
                                    const std::string &filelist,
                                    const std::string &hashes_file)    {


    m_key_file    = key_file;
    m_filelist    = filelist;
    m_hashes_file = hashes_file;

    // load list of files that is going to be encrypted
    m_file_list_handler->load_filelist_from_file(filelist);

    // Load RSA keys from key_file
    m_key_file_handler->load_keys_from_file(key_file, "");
    m_key_encryption_tool->set_rsa_keys(m_key_file_handler->get_pq(),
                                        m_key_file_handler->get_public_key(),
                                        m_key_file_handler->get_private_key_encrypted(),
                                        m_key_file_handler->get_rsa_type());

    // Generate random AES key
    const std::string input_files_hash_summary = m_file_list_handler->get_file_hash_summary();
    m_aes_key = m_key_encryption_tool->generate_aes_key(input_files_hash_summary);

    m_aes_wrapper = make_shared<AESWrapper>(m_aes_key, 256);

};

void BinaryEncryptor::create_encrypted_binary( const std::string &binary_address)   {
    m_output_binary = make_shared<ofstream>(binary_address, std::ios::binary | std::ios::out);

    // key summary containing RSA keys (with encrypted private key using password SHA3) and encrypted AES key (using RSA public key)
    const string key_summary_string = m_key_encryption_tool->produce_key_summary_string(m_aes_key);
    (*m_output_binary)  << std::noskipws << key_summary_string << "|";

    // dump names and sizes of the encrypted fiiles to string
    const string filelist_summary_string = m_file_list_handler->dump_filelist_to_string();
    encrypt_and_save_filelist_string(filelist_summary_string);

    // Encrypt actual files
    const vector<string> list_of_input_files                = m_file_list_handler->get_list_of_files_full_paths();
    std::vector<long long int> list_of_input_files_sizes    = m_file_list_handler->get_files_sizes();
    for (unsigned int i_file = 0; i_file < list_of_input_files.size(); i_file++)    {
        if (list_of_input_files_sizes[i_file] < 0)   {
            continue;
        }
        encrypt_and_save_input_file(list_of_input_files[i_file]);
    }
    m_output_binary->close();
};

void BinaryEncryptor::encrypt_and_save_input_file(const std::string &input_file_address)   {
    ifstream input_file(input_file_address, std::ios::binary | std::ios::in);
    unsigned char input_buffer[16];
    while(input_file.good())    {
        ReadFromFile(&input_file, input_buffer);
        m_aes_wrapper->encrypt(input_buffer);
        WriteToFile(m_output_binary.get(), input_buffer);
    }
    // TODO: check if the size of the file did not change from between it was checked and now
};

void BinaryEncryptor::encrypt_and_save_filelist_string(const std::string &filelist_string)   {
    const unsigned int original_length = filelist_string.length();
    const unsigned int number_of_aes_blocks_wo_padding = (original_length/16);

    unsigned char buffer[16];
    for (unsigned int i_block = 0; i_block < number_of_aes_blocks_wo_padding; i_block++)    {
        for (unsigned int i_char = 0; i_char < 16; i_char++)    {
            buffer[i_char] = filelist_string[i_block*16 + i_char];
        }
        m_aes_wrapper->encrypt(buffer);
        WriteToFile(m_output_binary.get(), buffer);
    };

    // padding of the filelist, to fit into 16 bytes block of AES
    unsigned int chars_in_padding_block = original_length % 16;
    for (unsigned int i_char = 0; i_char < chars_in_padding_block; i_char++)    {
            buffer[i_char] = filelist_string[number_of_aes_blocks_wo_padding*16 + i_char];
    }
    for (unsigned int i_char = chars_in_padding_block; i_char < 16; i_char++)    {
            buffer[i_char] = ';';
    }
    m_aes_wrapper->encrypt(buffer);
    WriteToFile(m_output_binary.get(), buffer);

    // 16 byte string signalizing the end of filelist
    for (unsigned int i_char = 0; i_char < 16; i_char++)    {
        buffer[i_char] = filelist_termination_string[i_char];
    }
    m_aes_wrapper->encrypt(buffer);
    WriteToFile(m_output_binary.get(), buffer);
};