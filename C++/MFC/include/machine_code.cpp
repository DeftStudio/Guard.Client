#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include "machine_code.h"
#pragma comment(lib, "IPHLPAPI.lib")  // 用于获取MAC地址
#pragma comment(lib, "wbemuuid.lib")  // 用于WMI
#pragma comment(lib, "Ole32.lib")
// 获取MAC地址
std::string GetMACAddress() {
	IP_ADAPTER_INFO AdapterInfo[16];       // 用来存储网卡信息
	DWORD dwBufLen = sizeof(AdapterInfo);  // 初始化为AdapterInfo大小

	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);  // 获取网卡信息
	if (dwStatus != ERROR_SUCCESS) {
		return "";
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	std::ostringstream macAddrStream;

	// 遍历网卡，获取第一个物理地址
	while (pAdapterInfo) {
		if (pAdapterInfo->AddressLength == 6) {  // 只取有效的物理地址
			for (int i = 0; i < 6; i++) {
				macAddrStream << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
				if (i < 5) {
					macAddrStream << ":";
				}
			}
			break;
		}
		pAdapterInfo = pAdapterInfo->Next;
	}

	return macAddrStream.str();
}
// 获取硬盘序列号
std::string GetDiskSerialNumber() {
	DWORD serialNumber = 0;
	if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
		std::ostringstream oss;
		oss << std::hex << serialNumber;
		return oss.str();
	}
	return "";
}
// 使用WMI获取主板序列号
std::string GetMotherboardSerialNumber() {
	HRESULT hres;

	// 初始化COM库
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		return "";
	}

	// 设置COM安全性
	hres = CoInitializeSecurity(
		NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);

	if (FAILED(hres)) {
		CoUninitialize();
		return "";
	}

	IWbemLocator* pLocator = NULL;

	// 创建WMI定位器
	hres = CoCreateInstance(
		CLSID_WbemLocator, 0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLocator);

	if (FAILED(hres)) {
		CoUninitialize();
		return "";
	}

	IWbemServices* pServices = NULL;

	// 连接到WMI服务
	hres = pLocator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL, NULL, 0, NULL, 0, 0, &pServices);

	if (FAILED(hres)) {
		pLocator->Release();
		CoUninitialize();
		return "";
	}

	// 设置WMI代理安全级别
	hres = CoSetProxyBlanket(
		pServices,
		RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
		NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE);

	if (FAILED(hres)) {
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return "";
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pServices->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT SerialNumber FROM Win32_BaseBoard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL, &pEnumerator);

	if (FAILED(hres)) {
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return "";
	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	std::string motherboardSerial;

	// 从查询结果中获取主板序列号
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (uReturn == 0) {
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hr)) {
			motherboardSerial = _bstr_t(vtProp.bstrVal);
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}

	pServices->Release();
	pLocator->Release();
	pEnumerator->Release();
	CoUninitialize();

	return motherboardSerial;
}
// 使用 OpenSSL 计算 SHA-256
std::string ComputeSHA256(const std::string& input) {
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP_MD_CTX");
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
		EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1 ||
		EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("Failed to compute SHA-256");
	}

	EVP_MD_CTX_free(ctx);

	std::ostringstream oss;
	for (unsigned int i = 0; i < hash_len; i++) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return oss.str();
}
// 生成序列号
std::string Machine_code::GenerateSystemSerialNumber() {
	std::string macAddress = GetMACAddress();
	std::string diskSerialNumber = GetDiskSerialNumber();
	std::string motherboardSerialNumber = GetMotherboardSerialNumber();

	// 将MAC地址、硬盘序列号和主板序列号组合起来生成唯一标识
	std::string machineIdentifier = macAddress + diskSerialNumber + motherboardSerialNumber;

	// 计算SHA-256哈希
	std::string machineCode = ComputeSHA256(machineIdentifier);

	return machineCode;
}