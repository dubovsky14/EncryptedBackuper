#include "../EncryptedBackuper/FileListHandler.h"

#include <iostream>
#include <vector>
#include <string>

using namespace std;
using namespace EncryptedBackuper;

int main(int argc, const char **argv)   {

    if (argc != 3)  {
        cout << "2 input arguments are expected:";
    }

    const std::string filelist_address = argv[1];

    FileListHandler filelist_handler;
    filelist_handler.load_filelist_from_file(filelist_address);
    filelist_handler.evaluate_file_sizes_from_disk();
    vector<string>          file_names = filelist_handler.get_list_of_files_names_only();
    vector<long long int>   file_sizes = filelist_handler.get_files_sizes();

    for (unsigned int i = 0; i < file_names.size(); i++)  {
        cout << file_names[i] << "\t\t" << file_sizes[i] << endl;
    }

    filelist_handler.create_files_hashes_file(argv[2]);
}