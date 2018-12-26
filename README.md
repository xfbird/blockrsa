# blockrsa
Block RSA encryption and decryption includes Base64 supporting public key encryption and private key decryption conforming to the standard PKCS#1 v1.5. Dependence on crypto/rand
Version 0.99

Because the original crypto / Rand only supports encrypted content less than Key length, all have BlockRsa Provide the following functions:

NewRSAKey creates RSA encryption objects based on the private key information provided. NewPubRSAKey creates RSA encryption objects based on the public key information provided. Base64RSA Encrypt Base64 encoding output string for public key encryption results of [] byte data Base64RSADecrypt decrypts Base64 encoding string ciphertext based on private key and outputs [] byte BlockRSA Encrypt performs public key-based encryption output for [] byte plaintext [] byte BlockRSADecrypt can't work for RSAKey that decrypts [] byte ciphertext based on private key and outputs [] byte selfless key information.

版本 0.99 主要是看中文，英文 是用百度 直接翻译的 由于 原版 crypto/rand 只支持 加密内容长度 小于 Key 长度 所有有了 BlockRsa 提供以下一些函数：

NewRSAKey 基于提供的私钥信息 创建RSA 加密对象。 NewPubRSAKey 基于提供的公钥信息 创建RSA 加密对象。 Base64RSAEncrypt 对于 []byte 数据 进行 公钥 加密 结果 进行 Base64 编码 输出字符串 Base64RSADecrypt 对于 Base64编码的字符串密文 进行 基于私钥 解密 输出 []byte BlockRSAEncrypt 对于 []byte 明文 进行 基于公钥 加密 输出 []byte BlockRSADecrypt 对于 []byte 密文 进行 基于私钥 解密 输出 []byte 无私钥信息的 RSAKey 无法工作
