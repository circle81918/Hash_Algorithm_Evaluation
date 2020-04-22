# HASH_Algorithm_Evaluation
 
Evaluating the performance of SHA1/SHA256 hash algorithm implemented by openssl, crypto and MSCript
+ OpenSSL : <https://www.openssl.org/>
+ Crypto++ : <https://www.cryptopp.com/>
+ MSCript : <https://msdn.microsoft.com/zh-tw/library/system.security.cryptography.hashalgorithm(v=vs.110).aspx> 

# Building with CMake

Currently, platform only support MSVC Win32 Release version.
* Open CMake GUI.
* Under Where is the source code, same path as source
* Under Where to build the binaries, same path as source plus build.
* Click Configure, Under Optional platform for generator, choose Win32
* Generate
