#include "verify.h"

std::string verify::trim_quotes(const std::string& str)
{
	if (str.empty()) {
		return str;
	}

	// Check if the first and last characters are double quotes
	if (str.front() == '"' && str.back() == '"') {
		// Remove the quotes
		return str.substr(1, str.size() - 2);
	}

	// If no quotes, return the original string
	return str;
}

void verify::handleErrors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

std::string verify::encryptWithPublicKey(const std::string& publicKeyPem, const std::string& data)
{
	BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), -1);
	EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!publicKey) {
		//std::cerr << "Error loading public key." << std::endl;
		handleErrors();
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
	if (!ctx) {
		//std::cerr << "Error creating context." << std::endl;
		handleErrors();
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		//std::cerr << "Error initializing encryption." << std::endl;
		handleErrors();
	}

	// 使用 SHA256 作为 OAEP 填充的哈希函数
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
		//std::cerr << "Error setting padding or hash function." << std::endl;
		handleErrors();
	}

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
		//std::cerr << "Error determining buffer length." << std::endl;
		handleErrors();
	}

	std::vector<unsigned char> encryptedData(outlen);
	if (EVP_PKEY_encrypt(ctx, encryptedData.data(), &outlen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
		//std::cerr << "Error encrypting data." << std::endl;
		handleErrors();
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(publicKey);
	BIO_free(bio);

	return base64Encode(encryptedData.data(), outlen);
}

EVP_PKEY* verify::loadPublicKeyFromString(const std::string& public_key_str)
{
	BIO* bio = BIO_new_mem_buf(public_key_str.data(), public_key_str.size());
	if (!bio)
		handleErrors();

	EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!public_key)
		handleErrors();

	return public_key;
}

bool verify::verifySignature(const std::string& publicKeyPem, const std::string& data, const std::vector<unsigned char>& signature)
{
	EVP_PKEY* evp_pkey = nullptr;
	bool result = false;

	// 读取公钥
	BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), publicKeyPem.size());
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
	SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

	// 验证签名
	int ret = EVP_PKEY_verify(ctx, signature.data(), signature.size(), hash, SHA256_DIGEST_LENGTH);

	if (ret == 1) {
		result = true;
	}
	// 清理资源
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_pkey);

	return result;
}

SYSTEMTIME verify::ConvertTimestampToSystemTime(uint64_t timestamp)
{
	// 定义Windows的起始时间：1601年1月1日
	const ULONGLONG EPOCH_DIFFERENCE = 11644473600ULL; // 1970到1601年之间的秒数
	const ULONGLONG SECONDS_TO_100NS = 10000000ULL;    // 1秒等于100纳秒
	const int BEIJING_TIME_OFFSET = 8 * 3600;          // 北京时间比UTC早8小时


	// 将UNIX时间戳转换为北京时间
	ULONGLONG beijingTimestamp = timestamp + BEIJING_TIME_OFFSET;

	// 将UNIX时间戳转换为以100纳秒为单位的Windows时间
	ULONGLONG windowsTimestamp = (beijingTimestamp + EPOCH_DIFFERENCE) * SECONDS_TO_100NS;

	// 将时间戳转换为FILETIME结构
	FILETIME ft;
	ft.dwLowDateTime = static_cast<DWORD>(windowsTimestamp & 0xFFFFFFFF);
	ft.dwHighDateTime = static_cast<DWORD>(windowsTimestamp >> 32);

	// 将FILETIME转换为SYSTEMTIME
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);

	return st;

}

void verify::HearthFunc(const std::string& data)
{
	//解密签名
	std::string temp = base64Decode(this->m_sign);
	//传入签名
	std::vector<unsigned char> m_signature(temp.begin(), temp.end());
	//验证签名
	bool verified = verifySignature(this->m_publickey, data, m_signature);
	if (!verified) {
		std::cout << oxorany("Illegal data.") << std::endl;
		this->m_Verify = oxorany(false);
	}
}

bool verify::Stripping_Equipment(const std::string& card)
{
	// 构造 请求包
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {oxorany("content-type"), oxorany("application/json")} };
	//先解密公钥
	this->m_publickey = base64Decode(PUBLIC_KEY);
	//加密卡密数据发送
	CradStr = encryptWithPublicKey(this->m_publickey, card);
	this->m_j_patch[oxorany("msg")] = CradStr;
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post(oxorany("/api/unbind"), headers, this->m_request_packet, oxorany("application/json")))
	{
		//取值
		auto jj = json::parse(oxorany(res->body));
		//check
		json check = jj[oxorany("check")];
		json si = check[oxorany("sign")];
		m_unix = check[oxorany("unix")];
		//status
		json status = jj[oxorany("status")];
		json ret = status[oxorany("code")];
		json retstr = status[oxorany("msg")];
		int rcode = ret;
		if (rcode != 1000)
		{
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Unbind = oxorany(false);
			return oxorany(false);
		}
		else
		{
			//取出签名值
			this->m_sign = trim_quotes(si.dump());
			//心跳
			HearthFunc(card);
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Unbind = oxorany(true);
			GetUnix();
			return oxorany(true);
		}
	}
	else {
		std::cout << oxorany("error code: ") << res.error() << std::endl;
		return oxorany(false);
	}
}

bool verify::Login(const std::string& card)
{
	// 构造 请求包
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {oxorany("content-type"), oxorany("application/json")} };
	//先解密公钥
	this->m_publickey = base64Decode(PUBLIC_KEY);
	//加密卡密数据发送
	CradStr = encryptWithPublicKey(this->m_publickey, card);
	this->m_j_patch[oxorany("msg")] = CradStr;
	this->m_j_patch[oxorany("device_code")] = GenerateSystemSerialNumber(); //机器码
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post(oxorany("/api/check"), headers, this->m_request_packet, oxorany("application/json")))
	{
		//取值
		auto jj = json::parse(oxorany(res->body));
		//check
		json check = jj[oxorany("check")];
		json si = check[oxorany("sign")];
		m_unix = check[oxorany("unix")];
		//status
		json status = jj[oxorany("status")];
		json ret = status[oxorany("code")];
		json retstr = status[oxorany("msg")];
		int rcode = ret;
		if (rcode != 1000)
		{
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Verify = oxorany(false);
			return oxorany(false);
		}
		else
		{
			//取出签名值
			this->m_sign = trim_quotes(si.dump());
			//心跳
			HearthFunc(card);
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Verify = oxorany(true);
			GetUnix();
			return oxorany(true);
		}
	}
	else {
		std::cout << oxorany("error code: ") << res.error() << std::endl;
		return oxorany(false);
	}
}

bool verify::GetVerify()
{
	return oxorany(this->m_Verify);
}

bool verify::GetUnbind()
{
	return oxorany(this->m_Unbind);
}

void verify::GetUnix()
{
	SYSTEMTIME time = ConvertTimestampToSystemTime(this->m_unix);
	std::cout << oxorany(u8"到期时间：") << time.wYear << "-" << time.wMonth << "-" << time.wDay << "-" << time.wHour << ":" << time.wMinute << ":" << time.wSecond;
}

verify::verify()
{
}
verify::verify(const std::string& card)
{
	// service ip
	// 构造 请求包
	httplib::Client cli(IP, PORT);
	httplib::Headers headers = { {oxorany("content-type"), oxorany("application/json")} };
	//先解密公钥
	//this->m_publickey = base64Decode(oxorany("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFtRGtuWTdXUUlsTUtYcUhFQ1cwMQpndEpjNUFOOXR1YmpkcXo5dDhPanZnN1VIS21CZjY5aVFibTMrejEvbzhqWnNNYmJQVEVQdXcxTU5EeDg4b3BaClQwb0lmWHk5MEk5cDVRczY4Z1gyemZicTQ3MHg0Skk3bUFOUzcrVzFyZE5mUW9PTm5EZjlzNXBJRStqKzYrcFgKRDh3blNBUjdPRmxVS3ZBcy9jWVNSbG1pQlpTbGcrYTJVMUNlZmVQV0ZHbTkvYVhSREJwZ0MyR2NrYU1EMW92YQp0Ni9UMmN6blI1NDFZMm9uQVVHZVFIUC9xaVhnTVJhaHVHbXo3ZnFSczlHZTBzWTVrakR5TTBJeEdNNEFTTWlzCllrRC9oN2ZBTU95ZFJCUndwWVBLRkJkK3pSL0JodjduRmpTaDVISXY2UzZ5VHdUV2pyVjQvL0h5ekRYUW8yencKbndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"));
	this->m_publickey = base64Decode(oxorany("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFtRGtuWTdXUUlsTUtYcUhFQ1cwMQpndEpjNUFOOXR1YmpkcXo5dDhPanZnN1VIS21CZjY5aVFibTMrejEvbzhqWnNNYmJQVEVQdXcxTU5EeDg4b3BaClQwb0lmWHk5MEk5cDVRczY4Z1gyemZicTQ3MHg0Skk3bUFOUzcrVzFyZE5mUW9PTm5EZjlzNXBJRStqKzYrcFgKRDh3blNBUjdPRmxVS3ZBcy9jWVNSbG1pQlpTbGcrYTJVMUNlZmVQV0ZHbTkvYVhSREJwZ0MyR2NrYU1EMW92YQp0Ni9UMmN6blI1NDFZMm9uQVVHZVFIUC9xaVhnTVJhaHVHbXo3ZnFSczlHZTBzWTVrakR5TTBJeEdNNEFTTWlzCllrRC9oN2ZBTU95ZFJCUndwWVBLRkJkK3pSL0JodjduRmpTaDVISXY2UzZ5VHdUV2pyVjQvL0h5ekRYUW8yencKbndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"));
	//加密卡密数据发送
	CradStr = encryptWithPublicKey(this->m_publickey,card);
	this->m_j_patch[oxorany("msg")] = CradStr;
	this->m_j_patch[oxorany("device_code")] = "2"; //机器码
	this->m_request_packet = m_j_patch.dump();
	if (auto res = cli.Post(oxorany("/api/check"), headers, this->m_request_packet, oxorany("application/json")))
	{
		//取值
		auto jj = json::parse(oxorany(res->body));
		//check
		json check = jj[oxorany("check")];
		json si = check[oxorany("sign")];
		//status
		json status = jj[oxorany("status")];
		json ret = status[oxorany("code")];
		json retstr = status[oxorany("msg")];
		int rcode = ret;
		if (rcode != 1000)
		{
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Verify = oxorany(false);
			return;
		}
		else
		{
			//取出签名值
			this->m_sign = trim_quotes(si.dump());
			//心跳
			HearthFunc(card);
			//输出登录结果
			std::cout << oxorany(trim_quotes(retstr)) << std::endl;
			this->m_Verify = oxorany(true);
			return;
		}
	}
	else {
		std::cout << oxorany("error code: ") << res.error() << std::endl;
		return ;
	}
}
verify::~verify()
{
}
