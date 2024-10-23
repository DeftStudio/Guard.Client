#pragma once
#include "httplib.h"
#include "json.hpp"
#include <iostream>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <vector>
#include "base64.h"
#include "oxorany.h"
#include "machine_code.h"
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#define IP oxorany("120.26.116.132")
#define PORT oxorany(7779)
#define PUBLIC_KEY oxorany("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyMW5pc1kxMzg5eGdSUFo2NHkrVgowMjFPWlNhSmpFVVQ2YVBQSHVLaEJ5d2Z4SDk3ME9xckJpWStXVXJRd1M4NnBGem4ybDBPTnE5cWpJVTlUZURPCkhqY0pINzNUNDFRU2RxMWZDYTk4dThZUkwwcmRoZU1mMkh3d2E5ZDF3Q05GeHZCMmZuY0hKQ2JoU2xQcVIwMDEKR1ZQbkRMbVNJQXpjYitNTDJicTdQVkVINWdyalpwbWhjYk5WWER4bG5mZTFLbzhJTURFNVN2L1lOZXhrcmhWYgpZWXFaclNlcXRSZ0FkcmVFTDdmY2tQMlRoZ1ltNDNFaWV1Vmp5dkZTcko3cjlZRzRDTVVTZ0p1aFNFcEUySDNlCkFhVGNaUzlXd3JZMmdCaGNIbFZlbDN4bzNVNFVDRm42VTZQcTVQajd6RTArSFJwVmxSa1VjVkZ4YnI1Znc1QmUKMVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t")
class verify : public base64, public Machine_code
{
private:
	// 公钥
	std::string m_publickey;
	// 卡密数据
	std::string CradStr;
	//json msg data
	using json = nlohmann::json;
	json m_j_patch = R"(
	{
    "msg": "",
	"device_code":""
	})"_json;
	//request packet
	std::string m_request_packet;
	//verify vaule
	bool m_Verify = oxorany(false);
	// 解綁
	bool m_Unbind = oxorany(false);
	// 时间戳
	uint64_t m_unix = 0;
	//Sign vaule
	std::string m_sign;
	// 取双引号内数据
	std::string trim_quotes(const std::string& str);
	//异常处理
	void handleErrors();
	// 使用公钥加密数据
	std::string encryptWithPublicKey(const std::string& publicKeyPem, const std::string& data);
	// 从字符串加载公钥
	EVP_PKEY* loadPublicKeyFromString(const std::string& public_key_str);
	// 使用 EVP_PKEY_CTX 验证 RSA+SHA256 签名 使用 PKCS#1 v1.5 填充模式验证签名
	bool verifySignature(const std::string& publicKeyPem, const std::string& data, const std::vector<unsigned char>& signature);
	// 时间戳到SYSTEMTIME结构体转换
	SYSTEMTIME ConvertTimestampToSystemTime(uint64_t timestamp);
public:
	// 获取登录结果
	bool GetVerify();
	// 获取解绑结果
	bool GetUnbind();
	// 获取到期时间
	void GetUnix();
	// 心跳call
	void HearthFunc(const std::string& card);
	// 解绑设备
	bool Stripping_Equipment(const std::string& card);
	// 单卡登录
	bool Login(const std::string& card);
	// Verify Run
	verify();
	verify(const std::string& card);
	~verify();
};
inline verify g_Verify;