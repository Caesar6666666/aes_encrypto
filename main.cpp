#include <argparse/argparse.hpp>
#include <iostream>
#include <filesystem>
#include <cryptopp/aes.h>
#include "aescrypto.h"
using namespace std;


int main(int argc, char* argv[])
{
    argparse::ArgumentParser program("aescrypto");
    program.add_argument("-o", "--output")
		.help("output file path")
		.default_value(string("<filename>.aes or <filename>"));
    program.add_argument("filename")
        .help("input file path");
    program.add_argument("-d", "--decrypt")
        .help("decrypt file")
        .default_value(false)
        .implicit_value(true);
    program.add_argument("-k", "--key")
        .help("aes key")
        .default_value(string("CAESAR"));
    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
		std::cout << err.what() << std::endl;
		std::cout << program;
		exit(1);
	}
    // check file exists
    if (!std::filesystem::exists(program.get<string>("filename")))
    {
		std::cout << "file not exists" << std::endl;
		exit(1);
	}
    string key{ program.get<string>("-k") };
    key.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
    init_iv();
    string output_path = program.get<string>("-o");
    if (!program.is_used("-o")) {
        if (!program.get<bool>("-d"))
        {
            output_path = program.get<string>("filename") + ".aes";
        }
        else {
            output_path = program.get<string>("filename").substr(0, program.get<string>("filename").length() - 4);
        }
    }
    if (program.get<bool>("-d") == true)
    {
		aes_decrypt_file(program.get<string>("filename"), output_path, program.get<string>("-k"));
	}
    else
    {
        aes_encrypt_file(program.get<string>("filename"), output_path, program.get<string>("-k"));
    }    
    return 0;
}