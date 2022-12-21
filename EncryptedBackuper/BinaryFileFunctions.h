#pragma once

#include <fstream>
#include <string>


namespace EncryptedBackuper   {

    const std::string filelist_termination_string = "/*FILELIST_END*/";

    inline void ReadFromFile(std::ifstream *input_file, unsigned char *buffer) {
        (*input_file)   >> std::noskipws
                        >> buffer[0] >> buffer[1] >> buffer[2] >> buffer[3] >> buffer[4] >> buffer[5] >> buffer[6] >> buffer[7]
                        >> buffer[8] >> buffer[9] >> buffer[10] >> buffer[11] >> buffer[12] >> buffer[13] >> buffer[14] >> buffer[15];
    };

    inline void WriteToFile(std::ofstream *output_file, const unsigned char *buffer) {
        (*output_file)  << std::noskipws
                        << (buffer[0]) << (buffer[1]) << (buffer[2]) << (buffer[3]) << (buffer[4]) << (buffer[5]) << (buffer[6]) << (buffer[7])
                        << (buffer[8]) << (buffer[9]) << (buffer[10]) << (buffer[11]) << (buffer[12]) << (buffer[13]) << (buffer[14]) << (buffer[15]);

    };
}