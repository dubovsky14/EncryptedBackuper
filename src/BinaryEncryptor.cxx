#include "../EncryptedBackuper/BinaryEncryptor.h"

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
    // key summary containing RSA keys (with encrypted private key using password SHA3) and encrypted AES key (using RSA public key)
    const string key_summary_string = m_key_encryption_tool->produce_key_summary_string(m_aes_key);

    // dump names and sizes of the encrypted fiiles to string
    const string filelist_summary_string = m_file_list_handler->dump_filelist_to_string();

    m_output_binary = make_shared<ofstream>(binary_address, std::ios::binary | std::ios::out);
    const vector<string> list_of_input_files                = m_file_list_handler->get_list_of_files_full_paths();
    std::vector<long long int> list_of_input_files_sizes    = m_file_list_handler->get_files_sizes();

    (*m_output_binary)  << std::noskipws << key_summary_string << ";";
    (*m_output_binary)  << std::noskipws << filelist_summary_string << ";";


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
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        m_aes_wrapper->encrypt(input_buffer);
        (*m_output_binary)  << std::noskipws
                            << (input_buffer[0]) << (input_buffer[1]) << (input_buffer[2]) << (input_buffer[3]) << (input_buffer[4]) << (input_buffer[5]) << (input_buffer[6]) << (input_buffer[7])
                            << (input_buffer[8]) << (input_buffer[9]) << (input_buffer[10]) << (input_buffer[11]) << (input_buffer[12]) << (input_buffer[13]) << (input_buffer[14]) << (input_buffer[15]);
    }
    // TODO: check if the size of the file did not change from between it was checked and now
};
