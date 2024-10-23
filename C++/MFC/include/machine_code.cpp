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
#pragma comment(lib, "IPHLPAPI.lib")  // ���ڻ�ȡMAC��ַ
#pragma comment(lib, "wbemuuid.lib")  // ����WMI
#pragma comment(lib, "Ole32.lib")
// ��ȡMAC��ַ
std::string GetMACAddress() {
	IP_ADAPTER_INFO AdapterInfo[16];       // �����洢������Ϣ
	DWORD dwBufLen = sizeof(AdapterInfo);  // ��ʼ��ΪAdapterInfo��С

	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);  // ��ȡ������Ϣ
	if (dwStatus != ERROR_SUCCESS) {
		return "";
	}

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	std::ostringstream macAddrStream;

	// ������������ȡ��һ�������ַ
	while (pAdapterInfo) {
		if (pAdapterInfo->AddressLength == 6) {  // ֻȡ��Ч�������ַ
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
// ��ȡӲ�����к�
std::string GetDiskSerialNumber() {
	DWORD serialNumber = 0;
	if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
		std::ostringstream oss;
		oss << std::hex << serialNumber;
		return oss.str();
	}
	return "";
}
// ʹ��WMI��ȡ�������к�
std::string GetMotherboardSerialNumber() {
	HRESULT hres;

	// ��ʼ��COM��
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		return "";
	}

	// ����COM��ȫ��
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

	// ����WMI��λ��
	hres = CoCreateInstance(
		CLSID_WbemLocator, 0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLocator);

	if (FAILED(hres)) {
		CoUninitialize();
		return "";
	}

	IWbemServices* pServices = NULL;

	// ���ӵ�WMI����
	hres = pLocator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL, NULL, 0, NULL, 0, 0, &pServices);

	if (FAILED(hres)) {
		pLocator->Release();
		CoUninitialize();
		return "";
	}

	// ����WMI����ȫ����
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

	// �Ӳ�ѯ����л�ȡ�������к�
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
// ʹ�� OpenSSL ���� SHA-256
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
// �������к�
std::string Machine_code::GenerateSystemSerialNumber() {
	std::string macAddress = GetMACAddress();
	std::string diskSerialNumber = GetDiskSerialNumber();
	std::string motherboardSerialNumber = GetMotherboardSerialNumber();

	// ��MAC��ַ��Ӳ�����кź��������к������������Ψһ��ʶ
	std::string machineIdentifier = macAddress + diskSerialNumber + motherboardSerialNumber;

	// ����SHA-256��ϣ
	std::string machineCode = ComputeSHA256(machineIdentifier);

	return machineCode;
}