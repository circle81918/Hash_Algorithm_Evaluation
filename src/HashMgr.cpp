#include "HashMgr.h"

FileHashMgr * FileHashMgr::_pInstance = NULL;

FileHashMgr * FileHashMgr::Instance()
{
	if (_pInstance == NULL)
	{
		_pInstance = new FileHashMgr();
	}
	return _pInstance;
}

FileHashMgr::FileHashMgr()
{
}

FileHashMgr::~FileHashMgr()
{
	if (_pInstance)
		delete(_pInstance);
}

bool FileHashMgr::CalculateSHA1_Crypto(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	CryptoPP::SHA1 sha1;

	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };
	unsigned char digest[CryptoPP::SHA1::DIGESTSIZE] = { 0 };

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		sha1.Update((const byte*)pszBuf, 65536);
	}

	sha1.Final(digest);

	memcpy(fileHashDigest.digest, digest, SHA1_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA1_DIGEST_LENGTH / sizeof(unsigned long);

	return true;
}

bool FileHashMgr::CalculateSHA256_Crypto(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	CryptoPP::SHA256 sha256;

	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };
	unsigned char digest[CryptoPP::SHA256::DIGESTSIZE] = { 0 };

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		sha256.Update((const byte*)pszBuf, 65536);
	}

	sha256.Final(digest);

	memcpy(fileHashDigest.digest, digest, SHA256_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA256_DIGEST_LENGTH / sizeof(unsigned long);

	return true;
}

bool FileHashMgr::CalculateSHA1_MSCrypt(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	bool bRet = true;

	unsigned char pszDigest[SHA1_DIGEST_LENGTH] = { 0 };
	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };

	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf("CryptAcquireContext failed !!\n");
		return false;
	}

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
		printf("CryptCreateHash failed !!\n");
		return false;
	}

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		bRet = CryptHashData(hHash, pszBuf, 65536, 0);
		if (!bRet)
		{
			printf("CryptHashData error !! ");
			return false;
		}
	}

	DWORD dwLenHash = SHA1_DIGEST_LENGTH;
	bRet = CryptGetHashParam(hHash, HP_HASHVAL, pszDigest, &dwLenHash, 0);
	if (!bRet)
	{
		printf("CryptGetHashParam failed !!\n");
		return false;
	}

	memcpy(fileHashDigest.digest, pszDigest, SHA1_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA1_DIGEST_LENGTH / sizeof(unsigned long);

	if (hHash != NULL)
	{
		CryptDestroyHash(hHash);
		hHash = NULL;
	}
	if (hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}

	return bRet;
}

bool FileHashMgr::CalculateSHA256_MSCrypt(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	bool bRet = true;

	unsigned char pszDigest[SHA256_DIGEST_LENGTH] = { 0 };
	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };

	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("CryptAcquireContext failed !!\n");
		return false;
	}

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	{
		printf("CryptCreateHash failed !!\n");
		return false;
	}

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		bRet = CryptHashData(hHash, pszBuf, 65536, 0);
		if (!bRet)
		{
			printf("CryptHashData error !! ");
			return false;
		}
	}

	DWORD dwLenHash = SHA256_DIGEST_LENGTH;
	bRet = CryptGetHashParam(hHash, HP_HASHVAL, pszDigest, &dwLenHash, 0);
	if (!bRet)
	{
		printf("CryptGetHashParam failed !!\n");
		return false;
	}

	memcpy(fileHashDigest.digest, pszDigest, SHA256_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA256_DIGEST_LENGTH / sizeof(unsigned long);

	if (hHash != NULL)
	{
		CryptDestroyHash(hHash);
		hHash = NULL;
	}
	if (hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}

	return bRet;
}

bool FileHashMgr::CalculateSHA1_OpenSSL(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	bool bRet = true;

	unsigned char pszDigest[SHA1_DIGEST_LENGTH] = { 0 };
	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };

	SHA_CTX shaCtx = { 0 };

	bRet = SHA1_Init(&shaCtx);
	if (!bRet)
	{
		printf("SHA1_Init error!!\n");
		return false;
	}

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		bRet = SHA1_Update(&shaCtx, (const void *)pszBuf, 65536);
		if (!bRet)
		{
			printf("SHA1_Update error !!\n");
			return false;
		}
	}

	bRet = SHA1_Final(pszDigest, &shaCtx);
	if (!bRet)
	{
		printf("SHA1_Final error !!\n");
		return false;
	}

	memcpy(fileHashDigest.digest, pszDigest, SHA1_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA1_DIGEST_LENGTH / sizeof(unsigned long);

	return true;
}

bool FileHashMgr::CalculateSHA256_OpenSSL(unsigned char * buf, int count, FileHashDigest & fileHashDigest)
{
	bool bRet = true;

	unsigned char pszDigest[SHA256_DIGEST_LENGTH] = { 0 };
	unsigned char pszBuf[HASH_BUF_SIZE] = { 0 };

	SHA256_CTX shaCtx = { 0 };

	bRet = SHA256_Init(&shaCtx);
	if (!bRet)
	{
		printf("SHA256_Init error!!\n");
		return false;
	}

	for (int i = 0; i<count; ++i)
	{
		memcpy(pszBuf, buf + 65536 * i, HASH_BUF_SIZE);
		bRet = SHA256_Update(&shaCtx, (const void *)pszBuf, 65536);
		if (!bRet)
		{
			printf("SHA256_Update error !!\n");
			return false;
		}
	}

	bRet = SHA256_Final(pszDigest, &shaCtx);
	if (!bRet)
	{
		printf("SHA256_Final error !!\n");
		return false;
	}

	memcpy(fileHashDigest.digest, pszDigest, SHA256_DIGEST_LENGTH * sizeof(unsigned char));
	fileHashDigest.len = SHA256_DIGEST_LENGTH / sizeof(unsigned long);

	return true;
}