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
using namespace std;

CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]{'C','A','E','S','A','R'}, iv[CryptoPP::AES::BLOCKSIZE]{};



string encrypt(const unsigned char* plainText, uint32_t len)
{
    string cipherText;

    //
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(plainText, len);
    stfEncryptor.MessageEnd();

    return cipherText;
}


void write_file(const string& output, const string path)
{
    ofstream out(path,ios::binary);
    out.write(output.c_str(), output.length());
    out.close();

    //cout << "wirte finish" << endl << endl;
}

string decrypt(string cipherTextHex)
{
    string decryptedText;

    //
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherTextHex.c_str()), cipherTextHex.size());

    stfDecryptor.MessageEnd();

    return decryptedText;
}

string read_file(const string& path)
{
    ifstream in;
    in.open(path, ios::binary);

    stringstream streambuffer;
    streambuffer << in.rdbuf();
    string text = std::move(streambuffer.str());
    in.close();
    /*for(auto i:text) cout << format("{:x}", (unsigned char)i);
    cout << "readCipher finish " << endl;*/

    return text;
}

void aes_encrypt_file(const string& input, const string& output, const string& key)
{
	ifstream in;
	in.open(input, ios::binary);

	stringstream streambuffer;
	streambuffer << in.rdbuf();
	string text = std::move(streambuffer.str());
	in.close();

	string chipherHex = std::move(encrypt((const unsigned char*)text.c_str(), text.length()));

    /*for (auto i : chipherHex) {
		cout << format("{:x}", (unsigned char)i);
	}
	cout << "$aesend" << endl;*/
	write_file(chipherHex, output);
}

void aes_decrypt_file(const string& input, const string& output, const string& key)
{
	string cipherTextHex = std::move(read_file(input));
	string outstring = decrypt(cipherTextHex);
	write_file(outstring, output);
}


int main(int argc, char* argv[])
{
    argparse::ArgumentParser program("aescrypto");
    program.add_argument("-o", "--output")
		.help("output file path")
		.default_value(string("output.aes"));
    program.add_argument("file")
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
    if (program["-d"] == true)
    {
		aes_decrypt_file(program.get<string>("file"), program.get<string>("-o"), program.get<string>("-k"));
	}
    else
    {
        aes_encrypt_file(program.get<string>("file"), program.get<string>("-o"), program.get<string>("-k"));
    }    
    return 0;
}

