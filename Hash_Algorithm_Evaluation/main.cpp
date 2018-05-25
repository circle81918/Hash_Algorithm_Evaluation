#include <iostream>
#include "HachMgr.h"

using namespace std;

#define TESTING_FILE_NUM   100

int GetMethodFromUser()
{
	int Method = 0;

	printf("Select the file hash method:\n");
	printf("  1. SHA1 OpenSSL Implementation\n");
	printf("  2. SHA1 MSCrypt Implementation\n");
	printf("  3. SHA1 Crypto++ Implementation\n");
	printf("  4. SHA256 OpenSSL Implementation\n");
	printf("  5. SHA256 MSCrypt Implementation\n");
	printf("  6. SHA256 Crypto++ Implementation\n");

	do {
		printf("Enter the option: (1,2,3,4,5,6)\n");
		cin >> Method;
		if (Method >= 1 && Method <= 6)
			break;
		else
			printf("Invalid option!\n");
	} while (1);

	return Method;
}

int main()
{
	int fileSize[5] = { 1, 2, 4, 8, 16};        
	int count[5] = { 16, 32, 64, 128, 256};    // fileSize(MB) / 64(KB)
	unsigned char **pszBuf = new unsigned char *[TESTING_FILE_NUM];

	DWORD dwTickStart = 0;
	DWORD dwTickEnd = 0;

	int Method = GetMethodFromUser();
	int Length = sizeof(fileSize) / sizeof(fileSize[0]);

	for (int i = 0; i < Length; ++i)
	{
		int size = fileSize[i];

		for (int j = 0; j < TESTING_FILE_NUM; ++j)
		{
			pszBuf[j] = new unsigned char [size * 1024 * 1024];
			if (pszBuf[j] == NULL)
				printf("Allocated pszbuf fail !!\n");
			memset(pszBuf[j], 0, size * 1024 * 1024);
		}

		dwTickStart = GetTickCount();
		for (int j = 0; j < TESTING_FILE_NUM; ++j)
		{
			FileHashDigest digest;
			switch (Method)
			{
			case 1:
				FileHashMgr::Instance()->CalculateSHA1_OpenSSL(pszBuf[j], count[i], digest);
				break;
			case 2:
				FileHashMgr::Instance()->CalculateSHA1_MSCrypt(pszBuf[j], count[i], digest);
				break;
			case 3:
				FileHashMgr::Instance()->CalculateSHA1_Crypto(pszBuf[j], count[i], digest);
				break;
			case 4:
				FileHashMgr::Instance()->CalculateSHA256_OpenSSL(pszBuf[j], count[i], digest);
				break;
			case 5:
				FileHashMgr::Instance()->CalculateSHA256_MSCrypt(pszBuf[j], count[i], digest);
				break;
			case 6:
				FileHashMgr::Instance()->CalculateSHA256_Crypto(pszBuf[j], count[i], digest);
				break;
			}
		}
		dwTickEnd = GetTickCount();
		printf("Test %d %dMB files time => <%lu> mill sec.\n", TESTING_FILE_NUM, size, dwTickEnd - dwTickStart);

		// free allocated memory
		for (int j = 0; j < TESTING_FILE_NUM; ++j)
			delete pszBuf[j];
	}
	delete pszBuf;

	system("pause");
	return 0;

}