#pragma once

#include <string>
#include <vector>

namespace EncryptedBackuper     {
    class FileListHandler   {
        public:
            FileListHandler();

            void    load_filelist_from_file(const std::string &filelist);

            void    evaluate_file_sizes_from_disk();

            void    create_files_hashes_file(const std::string &file_hashes_output_file)   const;

            bool    files_are_up_to_date(const std::string &reference_hashes_file) const;

            void    load_filelist_from_string(const std::string &filelist_string);

            std::string                 dump_filelist_to_string()   const;

            std::vector<std::string>    get_list_of_files_full_paths() const    {return m_filelist_full_paths;};
            std::vector<std::string>    get_list_of_files_names_only() const    {return m_filelist_filenames_only;};

            std::vector<long long int>  get_files_sizes() const                 {return m_files_sizes;};

        private:
            std::vector<std::string>        m_filelist_full_paths;
            std::vector<std::string>        m_filelist_filenames_only;
            std::vector<long long int>      m_files_sizes;

            static const std::string    s_file_name_vs_size_separator;
            static const std::string    s_between_files_separator;

            static long long int get_file_size(const std::string &file_address);

            static std::vector<std::string>    get_hashes_from_reference_hash_file(const std::string &reference_hashes_file);


    };
}