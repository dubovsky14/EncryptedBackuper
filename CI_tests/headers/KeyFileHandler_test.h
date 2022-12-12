#pragma once

#include <string>

namespace EncryptedBackuperTests    {
    void KeyFileHandler_test(unsigned int rsa_type);

    void CreateKeyFile(const std::string &key_file, const std::string &password, unsigned int rsa_key_lenght);

    void ValidateKeyFile(const std::string &key_file, const std::string &password, unsigned int rsa_key_lenght);

}