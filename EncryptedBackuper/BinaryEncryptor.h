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
                            const std::string &filelist_address);

            BinaryEncryptor(const std::string &key_file,
                            const std::vector<std::string> &files_to_enpcrypt);

            void create_encrypted_binary( const std::string &binary_address);

        private:
            KeyFileHandler     m_key_file_handler;
            FileListHandler    m_file_list_handler;
            KeyEncryptionTool  m_key_encryption_tool;

            std::unique_ptr<AESWrapper>         m_aes_wrapper           = nullptr;

            boost::multiprecision::cpp_int m_aes_key;
            boost::multiprecision::cpp_int m_aes_key_encrypted;

            std::string m_key_file;

            std::unique_ptr<std::ofstream> m_output_binary = nullptr;

            void encrypt_and_save_input_file(const std::string &input_file_address);

            void encrypt_and_save_filelist_string(const std::string &filelist_string);
    };
}