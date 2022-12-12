#include "../EncryptedBackuper/FileListHandler.h"

#include "../EncryptedBackuper/StringOperations.h"
#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"

#include <string>
#include <vector>
#include <fstream>

using namespace std;
using namespace EncryptedBackuper;

FileListHandler::FileListHandler()  {

};

void    FileListHandler::load_filelist_from_file(const std::string &filelist)   {
    m_filelist_full_paths.clear();
    m_filelist_filenames_only.clear();

    string line;
    ifstream input_file (filelist);
    if (input_file.is_open())    {
        while ( getline (input_file,line) )        {
            StripString(&line);
            if (StartsWith(line, "#") || line.length() == 0)    {
                continue;
            }
            m_filelist_full_paths.push_back(line);
            m_filelist_filenames_only.push_back(SplitString(line, "/").back());
        }
        input_file.close();
    }
    else    {
        throw std::string("Unable to open file \"" + filelist + "\"");
    }

    evaluate_file_sizes_from_disk();
};

void    FileListHandler::evaluate_file_sizes_from_disk() {
    m_files_sizes.clear();
    for (const std::string &file_address : m_filelist_full_paths)    {
        m_files_sizes.push_back(get_file_size(file_address));
    }
};

void    FileListHandler::create_files_hashes_file(const std::string &file_hashes_output_file)   const   {
    if (m_files_sizes.size() != m_filelist_full_paths.size())   {
        throw std::string("FileListHandler::create_files_hashes_file: vector of files and vector of file sizes are inconsistent!");
    }

    ofstream outfile;
    outfile.open(file_hashes_output_file);

    for (unsigned int i_file = 0; i_file < m_filelist_full_paths.size(); i_file++)  {
        if (m_files_sizes[i_file] < 0)  {
            outfile << "0x0" << endl;
            continue;
        }
        outfile << "0x" << convert_cpp_int_to_hex_string(calculate_sha3_from_file(m_filelist_full_paths[i_file], 256)) << endl;
    }

    outfile.close();

};

void    FileListHandler::files_are_up_to_date(const std::string &reference_hashes_file) const   {

};

void    FileListHandler::load_filelist_from_string(const std::string &filelist_string)  {

};

std::string FileListHandler::dump_filelist_to_string()   const  {

};

long long int FileListHandler::get_file_size(const std::string &file_address) {
    ifstream file(file_address, ios::binary);

    // if file does not exist
    if (file.fail())    return -1;

    const auto begin = file.tellg();
    file.seekg (0, ios::end);
    const auto end = file.tellg();
    file.close();
    return (end-begin);
};




std::vector<std::string>       m_filelist_full_paths;
std::vector<std::string>       m_filelist_filenames_only;
std::vector<long long int>     m_files_sizes;

