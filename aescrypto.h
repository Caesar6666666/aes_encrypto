// aescrypto.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once
#include <string>
void init_iv();

std::string encrypt(const char* text, size_t len, const std::string& key);


std::string decrypt(const char* cipherTextHex, size_t len, const std::string& key);

void aes_encrypt_file(const std::string& input_file, const std::string& output_file, const std::string& key);

void aes_decrypt_file(const std::string& input_file, const std::string& output_file, const std::string& key);
