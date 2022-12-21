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
    class BinaryEncryptor   {
        public:
            BinaryEncryptor(const std::string &key_file,
                            const std::string &filelist,
                            const std::string &hashes_file = "");

            void create_encrypted_binary( const std::string &binary_address);

        private:
            std::shared_ptr<KeyFileHandler>     m_key_file_handler      = std::make_shared<KeyFileHandler>();
            std::shared_ptr<FileListHandler>    m_file_list_handler     = std::make_shared<FileListHandler>();
            std::shared_ptr<KeyEncryptionTool>  m_key_encryption_tool   = std::make_shared<KeyEncryptionTool>();

            std::shared_ptr<AESWrapper>         m_aes_wrapper           = nullptr;

            boost::multiprecision::cpp_int m_aes_key;
            boost::multiprecision::cpp_int m_aes_key_encrypted;

            std::string m_key_file;
            std::string m_filelist;
            std::string m_hashes_file;

            std::shared_ptr<std::ofstream> m_output_binary = nullptr;

            void encrypt_and_save_input_file(const std::string &input_file_address);

            void encrypt_and_save_filelist_string(const std::string &filelist_string);
    };
}