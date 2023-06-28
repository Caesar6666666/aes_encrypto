// aescrypto.cpp: 定义应用程序的入口点。
//

#include "aescrypto.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <iomanip>
#include <format>
#include <cstdint>
#include <ranges>
#include <argparse/argparse.hpp>
#include <filesystem>
using namespace std;

CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]{};

void init_iv()
{
    std::fill(std::begin(iv), std::end(iv), 0x00);
}

string encrypt(const char* text, size_t len, const string& key)
{
    string cipherText;

    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const unsigned char*>(key.c_str()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(text), len);
    stfEncryptor.MessageEnd();

    return cipherText;
}


string decrypt(const char* cipherTextHex, size_t len, const string& key)
{
    string decryptedText;

    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const unsigned char*>(key.c_str()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherTextHex), len);

    stfDecryptor.MessageEnd();

    return decryptedText;
}

void aes_encrypt_file(const string& input_file, const string& output_file, const string& key)
{
	//read the input file
    std::uint64_t size = std::filesystem::file_size(input_file);
	ifstream in;
    in.open(input_file, ios::binary);

    const size_t blocksize = CryptoPP::AES::BLOCKSIZE * 1000 * 1000;  // 16MB
    unique_ptr<char[]> buffer{new char[blocksize]};

    //create the output file
    ofstream out;
    out.open(output_file, ios::trunc);
    out.close();

    out.open(output_file, ios::app | ios::binary);
    for (size_t i = 0; i < size; i+= blocksize)
    {
        in.read(buffer.get(), blocksize);
        string chipherHex{ std::move(encrypt(buffer.get(), in.gcount(), key))};
        out.write(chipherHex.c_str(), chipherHex.length());
    }
	out.close();
}

void aes_decrypt_file(const string& input_file, const string& output_file, const string& key)
{
    std::uint64_t size = std::filesystem::file_size(input_file);
    ifstream in;
    in.open(input_file, ios::binary);

    const size_t blocksize = CryptoPP::AES::BLOCKSIZE * 1000 * 1000;  // 16MB
    unique_ptr<char[]> buffer {new char[blocksize + 16]};

    //create the output file
    ofstream out;
    out.open(output_file, ios::trunc);
    out.close();
    out.open(output_file, ios::app | ios::binary);
    for (size_t i = 0; i < size; i += blocksize + 16)
    {
		in.read(buffer.get(), blocksize + 16);
		string chipherHex{ std::move(decrypt(buffer.get(), in.gcount(), key))};
        out.write(chipherHex.c_str(), chipherHex.length());
	}
    out.close();
}


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

