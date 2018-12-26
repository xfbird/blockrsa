// Copyright 2018 The ken . All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Version 0.99
// Because the original crypto / Rand only supports encrypted content less than Key length, all have BlockRsa
// Provide some functions:
// NewRSAKey creates RSA encryption objects based on the private key information provided.
// NewPubRSAKey creates RSA encryption objects based on the public key information provided.
// Base64RSA Encrypt Base64 encoding output string for public key encryption results of [] byte data
// Base64RSADecrypt decrypts Base64 encoding string ciphertext based on private key and outputs [] byte
// BlockRSA Encrypt performs public key-based encryption output for [] byte plaintext [] byte
// BlockRSADecrypt can't work for RSAKey that decrypts [] byte ciphertext based on private key and outputs [] byte selfless key information.

// 版本 0.99  主要是看中文，英文 是用百度 直接翻译的
// 由于 原版 crypto/rand 只支持 加密内容长度 小于 Key 长度 所有有了 BlockRsa
// 提供以下一些函数：
// NewRSAKey 基于提供的私钥信息 创建RSA 加密对象。
// NewPubRSAKey 基于提供的公钥信息 创建RSA 加密对象。
// Base64RSAEncrypt 对于 []byte 数据 进行 公钥 加密 结果 进行 Base64 编码 输出字符串
// Base64RSADecrypt 对于 Base64编码的字符串密文 进行 基于私钥 解密 输出 []byte
// BlockRSAEncrypt 对于 []byte 明文 进行 基于公钥 加密 输出  []byte
// BlockRSADecrypt 对于 []byte 密文 进行 基于私钥 解密 输出 []byte 无私钥信息的 RSAKey 无法工作
// Package rsa implements RSA encryption as specified in PKCS#1.

package blockrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
)

//RSAKey 基于RSA Key 信息 由于私钥 包含 公钥，因此 不再独立存储 公钥
//RSAKey RSA Key-based information no longer stores public keys independently because private keys contain public keys
type RSAKey struct {
	pri   *rsa.PrivateKey
	randr io.Reader
}

var (
	errorRSAKeyArg = errors.New("rsablock: missing key struct args")
)

//NewRSAKey 基于提供的私钥信息 创建RSA 加密对象。
//NewRSAKey Create RSA encryption objects based on the private key information provided.
func NewRSAKey(prevkeytxt []byte) (*RSAKey, error) {
	rsaKey := &RSAKey{nil, nil}
	block, _ := pem.Decode(prevkeytxt)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey.pri = privateKey
	rsaKey.randr = rand.Reader
	return rsaKey, nil
}

//NewPubRSAKey 基于提供的公钥信息 创建RSA 加密对象。仅用于 进行加密
//NewPubRSAKey RSA encryption object is created based on the public key information provided.
func NewPubRSAKey(prevkeytxt []byte) (*RSAKey, error) {
	rsaKey := &RSAKey{nil, nil}
	block, _ := pem.Decode(prevkeytxt)
	opub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey.pri.PublicKey = opub.(rsa.PublicKey)
	return rsaKey, nil
}

//Base64RSAEncrypt 对于 []byte 数据 进行 公钥 加密 结果 进行 Base64 编码 输出字符串
//Base64RSAEncrypt Base64 encoding output string for public key encryption results of [] byte data
func (rsak *RSAKey) Base64RSAEncrypt(plainText []byte) (string, error) {
	data, err := rsak.BlockRSAEncrypt(plainText)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

//Base64RSADecrypt 对于 Base64编码的字符串密文 进行 基于私钥 解密 输出 []byte
//Base64RSADecrypt Private key-based decryption output for Base64 encoding string ciphertext []byte
func (rsak *RSAKey) Base64RSADecrypt(ciphertext string) ([]byte, error) {
	ret, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return rsak.BlockRSADecrypt(ret)
}

//BlockRSAEncrypt 对于 []byte 明文 进行 基于公钥 加密 输出  []byte
//BlockRSAEncrypt For [] byte plaintext, output [] byte based on public key encryption
func (rsak *RSAKey) BlockRSAEncrypt(plainText []byte) (retEncrypyBlock []byte, err error) {
	if rsak.pri.PublicKey.N != nil && plainText != nil && len(plainText) > 0 {
		blocksize := rsak.pri.Size() - 11
		msglen := len(plainText)
		Resilen := msglen
		curpos := 0
		for {
			curlen := blocksize
			if Resilen < blocksize {
				curlen = Resilen
			}
			curblock := plainText[curpos : curpos+curlen]
			retEncodebs, err := rsa.EncryptPKCS1v15(rsak.randr, &rsak.pri.PublicKey, curblock)
			if err != nil {
				return nil, err
			}
			retEncrypyBlock = append(retEncrypyBlock, retEncodebs...)
			Resilen -= curlen
			curpos += curlen
			if Resilen <= 0 {
				break
			}
		}
	} else {
		return nil, errorRSAKeyArg
	}
	return retEncrypyBlock, nil
}

//BlockRSADecrypt 对于 []byte 密文 进行 基于私钥 解密 输出 []byte 无私钥信息的 RSAKey 无法工作
//BlockRSADecrypt RSAKey that decrypts [] byte ciphertext based on private key and outputs [] byte selfless key information cannot work
func (rsak *RSAKey) BlockRSADecrypt(ciphertext []byte) (retDecryptBlock []byte, err error) {
	if rsak.pri != nil && rsak.pri.D != nil && rsak.pri.PublicKey.N != nil && ciphertext != nil && len(ciphertext) > 0 {
		blocksize := rsak.pri.Size()
		msglen := len(ciphertext)
		Resilen := msglen
		curpos := 0
		for {
			curlen := blocksize
			if Resilen < blocksize {
				curlen = Resilen
			}
			curblock := ciphertext[curpos : curpos+curlen]
			retDecodebs, err := rsa.DecryptPKCS1v15(rsak.randr, rsak.pri, curblock)
			if err != nil {
				return nil, err
			}
			retDecryptBlock = append(retDecryptBlock, retDecodebs...)
			Resilen -= curlen
			curpos += curlen
			if Resilen <= 0 {
				break
			}
		}
	} else {
		return nil, errorRSAKeyArg
	}
	return retDecryptBlock, nil
}
