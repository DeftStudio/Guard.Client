// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

std::string base64Encode(const unsigned char* buffer, size_t length)
{
	BIO* bio = BIO_new(BIO_s_mem());
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// 忽略换行符
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(bio, buffer, length);
	BIO_flush(bio);

	BUF_MEM* buffer_ptr;
	BIO_get_mem_ptr(bio, &buffer_ptr);
	std::string encoded_data(buffer_ptr->data, buffer_ptr->length);

	BIO_free_all(bio);

	return encoded_data;
}

std::string base64Decode(const std::string& encoded_string)
{
	BIO* bio = BIO_new_mem_buf(encoded_string.data(), -1);
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// 忽略换行符
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	std::string decoded_string(encoded_string.length(), '\0');
	int decoded_length = BIO_read(bio, &decoded_string[0], encoded_string.length());

	BIO_free_all(bio);

	decoded_string.resize(decoded_length);  // 调整字符串到实际大小
	return decoded_string;
}

void handleErrors()
{
	MessageBoxA(0, "error ", "caption", 0);
	//ERR_print_errors_fp(stderr);
	//abort();
}

extern "C" __declspec(dllexport) bool verifySignature(LPCSTR publicKeyPem, LPCSTR data, LPCSTR signature)
{
	EVP_PKEY* evp_pkey = nullptr;
	bool result = false;
	std::string str = publicKeyPem;
	std::string str2 = data;
	std::string str3 = signature;

	std::vector<unsigned char> temp(str3.begin(), str3.end());
	// 读取公钥
	BIO* bio = BIO_new_mem_buf(str.data(), str.size());
	evp_pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!evp_pkey) {
		//std::cerr << "Failed to read public key." << std::endl;
		return false;
	}

	// 创建 EVP_PKEY_CTX 上下文
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_pkey, nullptr);
	if (!ctx) {
		//std::cerr << "Create EVP_PKEY_CTX error" << std::endl;
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// 初始化签名验证
	if (EVP_PKEY_verify_init(ctx) <= 0) {
		//std::cerr << "Failed to initialize signature verification. Procedure" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// 设置签名填充模式为 PKCS#1 v1.5
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		//std::cerr << "set PKCS#1 v1.5 error" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// 设置哈希算法为 SHA256
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		//std::cerr << "Description Failed to set the signature hashing algorithm" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(evp_pkey);
		return false;
	}

	// 计算数据的 SHA256 哈希
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(str2.c_str()), str2.size(), hash);

	// 验证签名
	int ret = EVP_PKEY_verify(ctx, temp.data(), temp.size(), hash, SHA256_DIGEST_LENGTH);

	if (ret == 1) {
		result = true;
	}
	// 清理资源
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_pkey);
	
	return result;
}

extern "C" __declspec(dllexport) LPCSTR encryptWithPublicKey(LPCSTR publicKeyPem, LPCSTR data)
{
	std::string str = publicKeyPem;
	std::string str2 = data;
	BIO* bio = BIO_new_mem_buf(str.data(), -1);
	EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!publicKey) {
		handleErrors();
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
	if (!ctx) {
		handleErrors();
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		handleErrors();
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
		handleErrors();
	}

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(str2.data()), str2.size()) <= 0) {
		handleErrors();
	}

	std::vector<unsigned char> encryptedData(outlen);
	if (EVP_PKEY_encrypt(ctx, encryptedData.data(), &outlen, reinterpret_cast<const unsigned char*>(str2.data()), str2.size()) <= 0) {
		handleErrors();
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(publicKey);
	BIO_free(bio);

	std::string ret = base64Encode(encryptedData.data(), outlen);

	// 分配内存并复制返回结果
	char* Cret = (char*)malloc(ret.length() + 1); // +1 for null terminator
	strcpy(Cret, ret.c_str());
	return Cret; // 返回动态分配的字符串
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case  DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}