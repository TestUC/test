//------------------------------------------------------------------------------
/*
    This file is part of Uchain
    Copyright (c) 2018 U.C. FOUNDTION.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <BeastConfig.h>
#include <ripple/basics/contract.h>
#include <openssl/pem.h>
#include <uchain/crypto/AES.h>

namespace ripple {

	// AES uses AES crypto algorithm.

	// A random IV is used to encrypt the message. If you need timestamps or need to tell the recipient
	// which key to use (his, yours, or ephemeral) you must add that data.
	// (Obviously, key information can't go in the encrypted portion anyway.)

	// Our ciphertext is all encrypted except the IV. The encrypted data decodes as follows:
	// 1) IV (unencrypted)
	// 2) Encrypted: Original plaintext
	// 3) Encrypted: Rest of block/padding

	// AES operations throw on any error such as a corrupt message or incorrect
	// key. They *must* be called in try/catch blocks.

	// Algorithmic choices:
#define ECIES_ENC_KEY_256  (256/8)             // Encryption key size
#define ECIES_ENC_KEY_128  (128/8)             // Encryption key size

#define ECIES_ENC_KEY_SIZE  (256/8)             // Encryption key size
#define ECIES_ENC_BLK_SIZE  (128/8)             // Encryption block size
#define ECIES_ENC_IV_TYPE   uint128             // Type used to hold IV

Blob encryptAES(Blob const& key, Blob const& plaintext, int keyByteLen)
{
	if (keyByteLen != ECIES_ENC_KEY_256 && keyByteLen != ECIES_ENC_KEY_128)
		Throw <std::runtime_error>("not supported");
	if (plaintext.size() == 0)
		Throw<std::runtime_error>("plaintext too short");
	if (key.size() < keyByteLen)
		Throw<std::runtime_error>("key too short");

	ECIES_ENC_IV_TYPE iv;
	memcpy(iv.begin(), &(key.front()), ECIES_ENC_BLK_SIZE);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_EncryptInit_ex(&ctx, (keyByteLen == ECIES_ENC_KEY_128) ? EVP_aes_128_cbc() : EVP_aes_256_cbc(),
		nullptr, &(key.front()), iv.begin()) != 1)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("init cipher ctx");
	}

	Blob out(plaintext.size() + ECIES_ENC_KEY_SIZE + ECIES_ENC_BLK_SIZE, 0);
	int len = 0, bytesWritten;

	if (EVP_EncryptUpdate(&ctx, &(out.front()), &bytesWritten, &(plaintext.front()), plaintext.size()) < 0)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("");
	}

	len = bytesWritten;


	if (EVP_EncryptFinal_ex(&ctx, &(out.front()) + len, &bytesWritten) < 0)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("encryption error");
	}

	len += bytesWritten;

	out.resize(len);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return out;
}

Blob decryptAES(Blob const& key, Blob const& ciphertext, int keyByteLen)
{
	if (keyByteLen != ECIES_ENC_KEY_256 && keyByteLen != ECIES_ENC_KEY_128)
		Throw <std::runtime_error>("not supported");
	if (ciphertext.size() == 0)
		Throw<std::runtime_error>("ciphertext is empty");
	if (key.size() < keyByteLen)
		Throw<std::runtime_error>("key too short");
	// extract IV
	ECIES_ENC_IV_TYPE iv;
	memcpy(iv.begin(), &(key.front()), ECIES_ENC_BLK_SIZE);

	int outlen = 0;
	// begin decrypting
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_DecryptInit_ex(&ctx, (keyByteLen == ECIES_ENC_KEY_128) ? EVP_aes_128_cbc() : EVP_aes_256_cbc(),
		nullptr, &(key.front()), iv.begin()) != 1)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("unable to init cipher");
	}

	Blob plaintext(ciphertext.size());

	if (EVP_DecryptUpdate(&ctx, &(plaintext.front()), &outlen,
		&(ciphertext.front()), ciphertext.size()) != 1)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("unable to extract plaintext");
	}

	// decrypt padding
	int flen = 0;

	if (EVP_DecryptFinal(&ctx, &(plaintext.front()) + outlen, &flen) != 1)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("plaintext had bad padding");
	}

	plaintext.resize(flen + outlen);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return plaintext;
}
} // ripple
