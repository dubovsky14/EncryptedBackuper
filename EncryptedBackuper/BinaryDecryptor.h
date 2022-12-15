#pragma once

#include <string>
#include <memory>
#include <fstream>

#include "../EncryptedBackuper/KeyFileHandler.h"
#include "../EncryptedBackuper/FileListHandler.h"
#include "../EncryptedBackuper/KeyEncryptionTool.h"
#include "../EncryptedBackuper/AESWrapper.h"

#include <boost/multiprecision/cpp_int.hpp>

namespace EncryptedBackuper     {
    class BinaryDecryptor   {
        public:
            BinaryDecryptor(const std::string &encrypted_file_address);

            void decrypt_files(const std::string &decrypted_files_folder, const std::string &password);

        private:
            std::shared_ptr<KeyFileHandler>     m_key_file_handler      = std::make_shared<KeyFileHandler>();
            std::shared_ptr<FileListHandler>    m_file_list_handler     = std::make_shared<FileListHandler>();
            std::shared_ptr<KeyEncryptionTool>  m_key_encryption_tool   = std::make_shared<KeyEncryptionTool>();

            std::shared_ptr<AESWrapper>         m_aes_wrapper           = nullptr;

            boost::multiprecision::cpp_int m_aes_key = -1;

            std::string m_encrypted_file_address;
            std::string m_decrypted_files_folder;

            std::shared_ptr<std::ifstream> m_input_binary = nullptr;

            void load_keys(const std::string &password);

            void read_list_of_files();

            std::string read_filelist_string();

            void decrypt_files();

            void decrypt_file(const std::string &file_address, long long int file_size);

            void print_out_keys()   const;

            void print_out_filelist()   const;

    };
}