#include <string.h>
#include <stdlib.h>
#include <windows.h>

#include "cryptopp5.65\sha.h"
#include "openssl\sha.h"

#define SHA256_DIGEST_LENGTH	32
#define SHA1_DIGEST_LENGTH	    20

#define SHA_MAX_DIGEST_LENGTH   32
#define HASH_BUF_SIZE		    65536

typedef struct _FileHashDigest
{
	unsigned char	digest[SHA_MAX_DIGEST_LENGTH];
	unsigned char	len;

	_FileHashDigest() : len(0) {
		memset(digest, 0, sizeof(unsigned char)*SHA_MAX_DIGEST_LENGTH);
	};

	bool operator==(const _FileHashDigest & b) const
	{
		if (len != b.len)
			return false;

		for (int i = 0; i<len; i++)
		{
			if (digest[i] != b.digest[i])
			{
				return false;
			}
		}
		return true;
	};

	bool operator<(const _FileHashDigest & b) const
	{
		if (len == 1 && b.len == 1)
			return digest[0] < b.digest[0];

		if (len > b.len)
			return false;
		if (len < b.len)
			return true;

		for (int i = 0; i<len; i++)
		{
			if (digest[i] > b.digest[i])
				return false;
			if (digest[i] < b.digest[i])
				return true;
			continue;
		}
		return false;
	};
} FileHashDigest;

class FileHashMgr
{
public:
	static FileHashMgr * Instance();

	bool CalculateSHA1_OpenSSL(	    /*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
	bool CalculateSHA1_MSCrypt(	    /*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
	bool CalculateSHA1_Crypto(	    /*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
	bool CalculateSHA256_OpenSSL(	/*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
	bool CalculateSHA256_MSCrypt(	/*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
	bool CalculateSHA256_Crypto(	/*__in*/	unsigned char * buf, int count,
		                            /*__out*/	FileHashDigest & fileHashDigest);
private:
	FileHashMgr();
	~FileHashMgr();

	static FileHashMgr * _pInstance;
};