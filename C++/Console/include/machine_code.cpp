#include <windows.h>
#include <iphlpapi.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "machine_code.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

// ��ȡ�������
std::string GetComputerNameStr() {
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(computerName);
	if (GetComputerNameA(computerName, &size)) {
		return std::string(computerName);
	}
	return "";
}

// ��ȡ����MAC��ַ
std::string GetMACAddress() {
	PIP_ADAPTER_INFO AdapterInfo;
	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG buflen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(AdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(buflen);
	}

	std::string macAddress;
	if (GetAdaptersInfo(AdapterInfo, &buflen) == NO_ERROR) {
		for (PIP_ADAPTER_INFO pAdapter = AdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
			std::ostringstream macStream;
			macStream << std::hex;
			for (int i = 0; i < pAdapter->AddressLength; ++i) {
				macStream << (i == 0 ? "" : "-") << (int)pAdapter->Address[i];
			}
			macAddress = macStream.str();
			break; // ֻ��ȡ��һ��������
		}
	}
	free(AdapterInfo);
	return macAddress;
}

// ��ȡӲ�����к�
std::string GetHardDiskSerial() {
	DWORD serialNum = 0;
	GetVolumeInformationA("C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0);
	std::ostringstream serialStream;
	serialStream << std::hex << serialNum;
	return serialStream.str();
}

// ��ȡWindows�汾
std::string GetWindowsVersion() {
	OSVERSIONINFOEXW osvi = { sizeof(osvi) };
	typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
	RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion) {
		RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
	}

	std::ostringstream versionStream;
	versionStream << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
	return versionStream.str();
}

// ����SHA-256��ϣֵ
std::string GenerateSHA256Hash(const std::string& data) {
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	const EVP_MD* md = EVP_sha256();

	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int lengthOfHash = 0;

	EVP_DigestInit_ex(context, md, NULL);
	EVP_DigestUpdate(context, data.c_str(), data.size());
	EVP_DigestFinal_ex(context, hash, &lengthOfHash);
	EVP_MD_CTX_free(context);

	std::ostringstream hashStream;
	for (unsigned int i = 0; i < lengthOfHash; ++i) {
		hashStream << std::hex << (int)hash[i];
	}

	return hashStream.str();
}

// �������к�
std::string Machine_code::GenerateSystemSerialNumber() {
	std::string computerName = GetComputerNameStr();
	std::string macAddress = GetMACAddress();
	std::string hardDiskSerial = GetHardDiskSerial();
	std::string windowsVersion = GetWindowsVersion();
	// ��������Ϣ���
	std::string combinedData = computerName + macAddress + hardDiskSerial + windowsVersion;
	// ����SHA-256��ϣֵ
	std::string hash = GenerateSHA256Hash(combinedData);
	// ����ǰ16���ַ���Ϊ���к�
	return hash;
}