// aescrypto.cpp: 定义应用程序的入口点。
//
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
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
    size_t size = std::filesystem::file_size(input_file);
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
    size_t size = std::filesystem::file_size(input_file);
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