#include "../EncryptedBackuper/FileListHandler.h"

#include "../EncryptedBackuper/StringOperations.h"
#include "../EncryptedBackuper/RSA_related_math_functions.h"
#include "../EncryptedBackuper/SHA3Calculator.h"

#include <string>
#include <vector>
#include <fstream>

using namespace std;
using namespace EncryptedBackuper;

const std::string    FileListHandler::s_file_name_vs_size_separator   = "*";
const std::string    FileListHandler::s_between_files_separator       = ":";

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

bool    FileListHandler::files_are_up_to_date(const std::string &reference_hashes_file) const   {
    const vector<string> reference_hashes = get_hashes_from_reference_hash_file(reference_hashes_file);
    vector<string> current_hashes;
    for (unsigned int i_file = 0; i_file < m_filelist_full_paths.size(); i_file++)  {
        if (m_files_sizes[i_file] < 0)  {
            current_hashes.push_back("0x0");
            continue;
        }
        current_hashes.push_back("0x" + convert_cpp_int_to_hex_string(calculate_sha3_from_file(m_filelist_full_paths[i_file], 256)));
    }

    if (reference_hashes.size() != current_hashes.size()) {
        return false;
    }
    for (unsigned int i_file = 0; i_file < current_hashes.size(); i_file++)  {
        if (current_hashes[i_file] != reference_hashes[i_file])  {
            return false;
        }
    }

    return true;
};

void    FileListHandler::load_filelist_from_string(const std::string &filelist_string)  {
    m_filelist_full_paths.clear();
    m_filelist_filenames_only.clear();
    m_files_sizes.clear();
    vector<string> name_and_size_vector = SplitString(filelist_string, s_between_files_separator);
    for (const std::string &name_and_size_string : name_and_size_vector)    {
        vector<string> name_and_size = SplitString(name_and_size_string, s_file_name_vs_size_separator);
        if (name_and_size.size() != 2)  {
            throw std::string("FileListHandler::load_filelist_from_string : invalid input string");
        }
        if (!StringIsInt(name_and_size[1])) {
            throw std::string("FileListHandler::load_filelist_from_string : invalid input string");
        }
        m_filelist_filenames_only.push_back(name_and_size[0]);
        m_files_sizes.push_back(std::stoi(name_and_size[1]));
    }
};

std::string FileListHandler::dump_filelist_to_string()   const  {
    //"file1_name:file1_size_in_bytes*file2_name:file2_size_in_bytes ..."
    string result;
    if (m_files_sizes.size() != m_filelist_filenames_only.size())   {
        throw std::string("FileListHandler::create_files_hashes_file: vector of files and vector of file sizes are inconsistent!");
    }
    for (unsigned int i_file = 0; i_file < m_filelist_filenames_only.size(); i_file++)  {
        result =    result + (i_file == 0 ? "" : s_between_files_separator) +
                    m_filelist_filenames_only[i_file] + s_file_name_vs_size_separator +
                    std::to_string(m_files_sizes[i_file]);
    }
    return result;
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

std::string FileListHandler::get_file_hash_summary() const  {
    string result;
    for (unsigned int i_file = 0; i_file < m_filelist_full_paths.size(); i_file++)  {
        if (m_files_sizes[i_file] > 0)  {
            result = result + ("0x" + convert_cpp_int_to_hex_string(calculate_sha3_from_file(m_filelist_full_paths[i_file], 256)));
        }
    }
    return result;
};

std::vector<std::string>    FileListHandler::get_hashes_from_reference_hash_file(const std::string &reference_hashes_file)   {
    vector<string> result;
    string line;
    ifstream input_file (reference_hashes_file);
    if (input_file.is_open())    {
        while ( getline (input_file,line) )        {
            StripString(&line);
            if (line.length() == 0)    {
                continue;
            }
            result.push_back(line);
        }
        input_file.close();
    }
    else    {
        throw std::string("Unable to open file \"" + reference_hashes_file + "\"");
    }
    return result;
};


