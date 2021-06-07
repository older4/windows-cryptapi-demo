#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")
#pragma warning(disable : 4996)
#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*3) // an output buffer must be a multiple of the key size

enum Mode
{
	Encrypt_mode,
	Decrypt_mode,
	Random_Encrypt_mode,
	Nonhashed_Decrypt_mode,
};

void BytesFromHexString(BYTE* data, const char* string) {
	int len = (int)strlen(string);
	for (int i = 0; i < len; i += 2) {
		unsigned int x;
		sscanf((char*)(string + i), "%02x", &x);
		data[i / 2] = x;
	}
}

//params: <input file> <output file> <is decrypt mode> <key>
int wmain(int argc, wchar_t* argv[])
{
	if (argc < 4) {
		printf("params: <input file> <output file> <is decrypt mode> [*key]\n");
		printf(
			"is decrypt mode:\n"
			"	0: Decrypt(with hase) mode\n"
			"	1: Decrypt(from keyblob string) mode\n"
			"	2: Encrypt mode\n"
			"	3: Random Encrypt mode\n");
		system("pause");
		return 0;
	}
	printf("waiting for start...");
	system("pause");
	wchar_t* filename = argv[1];
	wchar_t* filename2 = argv[2];

	wchar_t default_key[] = L"3igcZhRdWq96m3GUmTAiv9";
	wchar_t* key_str = default_key;

	Mode process_Mode = Decrypt_mode;

	if (argv[3][0] == L'0') {
		printf("Decrypt(with hased) mode\n");
		process_Mode = Decrypt_mode;
	}
	else if (argv[3][0] == L'1') {
		printf("Decrypt(from keyblob string) mode\n");
		process_Mode = Nonhashed_Decrypt_mode;
	}
	else if (argv[3][0] == L'2') {
		printf("Encrypt mode\n");
		process_Mode = Encrypt_mode;
	}
	else if (argv[3][0] == L'3') {
		printf("Random Encrypt mode\n");
		process_Mode = Random_Encrypt_mode;
	}


	if (argc >= 5) {
		key_str = argv[4];
	}
	size_t len = lstrlenW(key_str);

	printf("Key: %S\n", key_str);
	printf("Key len: %#x\n", len);
	printf("Input File: %S\n", filename);
	printf("Output File: %S\n", filename2);
	printf("----\n");

	HANDLE hInpFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInpFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open input file!\n");
		system("pause");
		return (-1);
	}
	HANDLE hOutFile = CreateFileW(filename2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open output file!\n");
		system("pause");
		return (-1);
	}

	if (process_Mode == Decrypt_mode) {
		printf("DECRYPTING\n");
	}
	else if (process_Mode == Encrypt_mode) {
		printf("ENCRYPTING\n");
	}
	else if (process_Mode == Random_Encrypt_mode) {
		printf("Random Encrypt\n");
	}

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return dwStatus;
	}
	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return dwStatus;
	}

	HCRYPTKEY hKey;

	// Gen hkey from CryptGenKey
	if (process_Mode == Random_Encrypt_mode) {
		if (!CryptGenKey(hProv, CALG_AES_128, CRYPT_EXPORTABLE, &hKey)) {
			DWORD err = GetLastError();
			printf("CryptGenKey Failed : %#x\n", err);
			system("pause");
			return (-1);
		}

		DWORD keyLengh = 0;

		CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &keyLengh);
		printf("KEYBLOB Length: %d\n", keyLengh);

		BYTE* keyBlob = (BYTE*)malloc(keyLengh);
		CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, keyBlob, &keyLengh);

		printf("Header： ");
		for (int i = 0; i < 12; i++) {
			printf("%02x", keyBlob[i]);
		}
		printf("\n");

		printf("Key： ");
		for (int i = 12; i < keyLengh; i++) {
			printf("%02x", keyBlob[i]);
		}
		printf("\n");

		printf("PLAINTEXTKEYBLOB: Input the below string as a password to decrypt.\n");
		printf("---------------------------\n");
		for (int i = 0; i < keyLengh; i++) {
			printf("%02x", keyBlob[i]);
		}
		printf("\n---------------------------\n");
	}
	// Gen hkey from inputted pass(CALG_AES_128)
	else if (process_Mode == Nonhashed_Decrypt_mode) {
		BYTE keyBlob[28];
		char pMBBuffer[100];
		wcstombs(pMBBuffer, key_str, 100);
		BytesFromHexString(keyBlob, pMBBuffer);

		if (!CryptImportKey(hProv, (BYTE*)keyBlob, 28, 0, CRYPT_EXPORTABLE, &hKey)) {
			DWORD err = GetLastError();
			printf("CryptImportKey Failed : %#x\n", err);
			system("pause");
			return (-1);
		}

	}
	// Gen hkey from inputted pass phrase hash value.
	else {
		if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
			DWORD err = GetLastError();
			printf("CryptHashData Failed : %#x\n", err);
			system("pause");
			return (-1);
		}
		printf("[+] CryptHashData Success\n");

		if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
			dwStatus = GetLastError();
			printf("CryptDeriveKey failed: %x\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			system("pause");
			return dwStatus;
		}
		printf("[+] CryptDeriveKey Success\n");
	}


	const size_t chunk_size = CHUNK_SIZE;
	BYTE chunk[chunk_size] = { 0 };
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;

	DWORD inputSize = GetFileSize(hInpFile, NULL);

	while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize == inputSize) {
			isFinal = TRUE;
			printf("Final chunk set.\n");
		}

		if (process_Mode == Decrypt_mode || process_Mode == Nonhashed_Decrypt_mode) {
			if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
				dwStatus = GetLastError();
				printf("[-] CryptDecrypt failed: %x\n", dwStatus);
				CryptReleaseContext(hProv, 0);
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
				printf("[-] CryptEncrypt failed\n");
				break;
			}
		}

		DWORD written = 0;
		if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
			printf("writing failed!\n");
			break;
		}
		memset(chunk, 0, chunk_size);
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);

	CloseHandle(hInpFile);
	CloseHandle(hOutFile);
	printf("Finished. Processed %#x bytes.\n", readTotalSize);
	return 0;
}