#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <string>
#include <iostream>

using namespace std;
using namespace EncryptedBackuper;
using namespace boost::multiprecision;

int main(int argc, const char **argv)   {
    if (argc != 3)  {
        cout << "Two input arguments are expected:";
        cout << "\t1st = length of RSA key:";
        cout << "\t2nd = address of the file with generated keys";
    }

    const unsigned int rsa_type = std::stoi(std::string(argv[1]));

    cout << "Please type in your password and hit enter\n";
    string password;
    cin >> password;

    const unsigned int sha3_type = 512;
    SHA3Calculator password_hasher(sha3_type);
    password_hasher.hash_message(password);
    password = "";

    cpp_int password_extended_hash = password_hasher.get_hash();
    const unsigned int required_number_of_hashes = rsa_type/sha3_type;
    const cpp_int bitshift_constant = square_and_multiply(cpp_int(2), sha3_type, 0);
    for (unsigned int i = 1; i<required_number_of_hashes; i++)   {
        password_extended_hash *= bitshift_constant;
        password_extended_hash += password_hasher.apply_next_keccak_and_get_output();
    }

    boost::multiprecision::cpp_int pq, private_key, public_key(65537);

    bool valid_key = false;
    while (!valid_key) {
        valid_key = generate_rsa_keys(&pq, &private_key, public_key, 512);
    }

    const string string_pq          = "0x" + convert_cpp_int_to_string(pq);
    const string string_public_key  = "0x" + convert_cpp_int_to_string(public_key);
    const string string_private_key = "0x" + convert_cpp_int_to_string(private_key+password_extended_hash);

    const string message_to_sign = string_pq + string_public_key + string_private_key;
    const cpp_int message_hash = calculate_sha3(message_to_sign, 512);
    const cpp_int message_rsa_signature = square_and_multiply(message_hash, private_key, pq);

    cout << "pq = " << string_pq << endl;
    cout << "key_public = " << string_public_key << endl;
    cout << "key_private (after password addition) = " << string_private_key << endl;
    cout << "signature = " << hex << message_rsa_signature << endl;



    return 0;
};