#include "../EncryptedBackuper/KeyEncryptionTool.h"

#include "../EncryptedBackuper/SHA3Calculator.h"
#include "../EncryptedBackuper/RandomNumberGenerator.h"
#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/StringOperations.h"


#include <boost/multiprecision/cpp_int.hpp>


#include <string>
#include <map>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

const string KeyEncryptionTool::s_keyword_rsa_length                  = "rsa_length";
const string KeyEncryptionTool::s_keyword_rsa_pq                      = "rsa_pq";
const string KeyEncryptionTool::s_keyword_rsa_public_key              = "rsa_public_key";
const string KeyEncryptionTool::s_keyword_rsa_private_key_encrypted   = "rsa_private_encrypted";
const string KeyEncryptionTool::s_keyword_aes_key_encrypted           = "aes_key_encrypted";

void KeyEncryptionTool::set_rsa_keys(   const boost::multiprecision::cpp_int &pq,
                                        const boost::multiprecision::cpp_int &public_key,
                                        const boost::multiprecision::cpp_int &private_key_xor_password_hash,
                                        unsigned int rsa_key_size)  {
    m_pq                            = pq;
    m_public_key                    = public_key;
    m_private_key_xor_password_hash = private_key_xor_password_hash;
    m_rsa_key_size                  = rsa_key_size;
};


boost::multiprecision::cpp_int KeyEncryptionTool::generate_aes_key(const std::string &file_hashes_summary) const    {
    RandomNumberGenerator rng(256);
    const string random_number = convert_cpp_int_to_hex_string(rng.Random());

    return calculate_sha3(random_number + file_hashes_summary, 256);
};

boost::multiprecision::cpp_int KeyEncryptionTool::encrypt_aes_key(const boost::multiprecision::cpp_int &aes_key)    const   {
    if (aes_key > m_pq) {
        throw std::string("KeyEncryptionTool::encrypt_aes_key: Unable to encrypt. The provided AES key is larger than P*Q expresion in RSA key");
    }
    return square_and_multiply(aes_key, m_public_key, m_pq);
};

boost::multiprecision::cpp_int KeyEncryptionTool::decrypt_aes_key(  const boost::multiprecision::cpp_int &aes_key_encrypted,
                                                                    const std::string &password)    const   {
    if (aes_key_encrypted > m_pq) {
        throw std::string("KeyEncryptionTool::dencrypt_aes_key: Unable to decrypt. The provided encrypted AES key is larger than P*Q expresion in RSA key");
    }
    cpp_int rsa_private_key = decrypt_private_key(m_private_key_xor_password_hash, password, m_rsa_key_size);
    return square_and_multiply(aes_key_encrypted, rsa_private_key, m_pq);
};

std::string KeyEncryptionTool::produce_key_summary_string(const boost::multiprecision::cpp_int &aes_key)    const    {
    //rsa_length=value;rsa_pq=value;rsa_public_key=value;rsa_private_encrypted=value;aes_key_encrypted=value
    const cpp_int aes_key_encrypted = encrypt_aes_key(aes_key);

    string result =  s_keyword_rsa_length + "=" + std::to_string(m_rsa_key_size);
    result = result + ";" + s_keyword_rsa_pq + "=0x" + convert_cpp_int_to_hex_string(m_pq);
    result = result + ";" + s_keyword_rsa_public_key + "=0x" + convert_cpp_int_to_hex_string(m_public_key);
    result = result + ";" + s_keyword_rsa_private_key_encrypted + "=0x" + convert_cpp_int_to_hex_string(m_private_key_xor_password_hash);
    result = result + ";" + s_keyword_aes_key_encrypted + "=0x" + convert_cpp_int_to_hex_string(aes_key_encrypted);

    return result;
};

void KeyEncryptionTool::load_key_summary_string(const std::string key_summary_string, const std::string &password)   {
    try {
        map<string,string> summary_key_map;
        const vector<string> vector_key_name_vs_key_value = SplitString(key_summary_string, ";");
        for (const string &name_and_value_string : vector_key_name_vs_key_value)   {
            const vector<string> name_and_value = SplitString(name_and_value_string, "=");
            if (name_and_value.size() != 2)  {
                continue;
            }
            summary_key_map[name_and_value[0]] = name_and_value[1];
        }

        auto read_value = [summary_key_map](const string &name) {
            if (summary_key_map.find(name) == summary_key_map.end())    {
                throw std::string("Unable to read key summary string. Undefined option: " + name);
            }
            return summary_key_map.at(name);
        };

        m_rsa_key_size                  = std::stoi(read_value(s_keyword_rsa_length));
        m_pq                            = cpp_int(read_value(s_keyword_rsa_pq));
        m_public_key                    = cpp_int(read_value(s_keyword_rsa_public_key));
        m_private_key_xor_password_hash = cpp_int(read_value(s_keyword_rsa_private_key_encrypted));
        m_aes_key_encrypted             = cpp_int(read_value(s_keyword_aes_key_encrypted));

        if (password.length() > 0)  {
            m_private_key = decrypt_private_key(m_private_key_xor_password_hash, password, m_rsa_key_size);
            m_aes_key = decrypt_aes_key(m_aes_key_encrypted, password);
        }
    }
    catch(boost::wrapexcept<std::runtime_error> &invalid_key_input) {
        throw string("Unable to load key summary string. One of the keys is not a number!");
    }
    catch (const std::invalid_argument & e) {
        throw string("Unable to load key summary string. Invalid RSA length!");
    }
    catch (const std::out_of_range & e) {
        throw string("Unable to load key summary string. Invalid RSA length!");
    }
};

boost::multiprecision::cpp_int  KeyEncryptionTool::encrypt_private_key( const boost::multiprecision::cpp_int &private_key,
                                                                        const std::string &password, unsigned int rsa_type) {

    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, rsa_type);
    return private_key ^ password_extended_hash;
};

boost::multiprecision::cpp_int  KeyEncryptionTool::decrypt_private_key( const boost::multiprecision::cpp_int &private_key_encrypted,
                                                                        const std::string &password, unsigned int rsa_type) {

    cpp_int password_extended_hash = generate_rsa_bit_length_size_password_hash(password, rsa_type);
    return private_key_encrypted ^ password_extended_hash;
};


boost::multiprecision::cpp_int  KeyEncryptionTool::generate_rsa_bit_length_size_password_hash(  const std::string &password,
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

bool KeyEncryptionTool::validate_keys() {
    if (m_private_key<0)    {
        return false;
    }

    RandomNumberGenerator rng(512);
    for (unsigned int i = 0; i < 10; i++)   {
        const cpp_int message       = rng.Random();
        const cpp_int signature     = square_and_multiply(message, m_private_key, m_pq);
        const cpp_int signature_decr= square_and_multiply(signature, m_public_key, m_pq);
        if (signature_decr != message)  {
            return false;
        }
    }
    return true;
};