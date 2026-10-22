/*	$OpenBSD: ssherr.c,v 1.13 2026/09/16 00:31:27 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#شامل <errno.h>
#شامل <string.h>
#شامل "ssherr.h"

ثابت نویسه *
ssh_err(صحیح n)
{
	ثابت نویسه *پیام = پوچ;

	انتخاب (n) {
	حالت SSH_ERR_SUCCESS:
		بازگشت "success";
	حالت SSH_ERR_INTERNAL_ERROR:
		بازگشت "unexpected internal error";
	حالت SSH_ERR_ALLOC_FAIL:
		بازگشت "memory allocation failed";
	حالت SSH_ERR_MESSAGE_INCOMPLETE:
		بازگشت "incomplete message";
	حالت SSH_ERR_INVALID_FORMAT:
		بازگشت "invalid format";
	حالت SSH_ERR_BIGNUM_IS_NEGATIVE:
		بازگشت "bignum is negative";
	حالت SSH_ERR_STRING_TOO_LARGE:
		بازگشت "string is too large";
	حالت SSH_ERR_BIGNUM_TOO_LARGE:
		بازگشت "bignum is too large";
	حالت SSH_ERR_ECPOINT_TOO_LARGE:
		بازگشت "elliptic curve point is too large";
	حالت SSH_ERR_NO_BUFFER_SPACE:
		بازگشت "insufficient buffer space";
	حالت SSH_ERR_INVALID_ARGUMENT:
		بازگشت "invalid argument";
	حالت SSH_ERR_کلید_BITS_MISMATCH:
		بازگشت "key bits do not match";
	حالت SSH_ERR_EC_CURVE_INVALID:
		بازگشت "invalid elliptic curve";
	حالت SSH_ERR_کلید_TYPE_MISMATCH:
		بازگشت "key type does not match";
	حالت SSH_ERR_کلید_TYPE_UNKNOWN:
		بازگشت "unknown or unsupported key type";
	حالت SSH_ERR_EC_CURVE_MISMATCH:
		بازگشت "elliptic curve does not match";
	حالت SSH_ERR_EXPECTED_CERT:
		بازگشت "plain key provided where certificate required";
	حالت SSH_ERR_کلید_LACKS_CERTBLOB:
		بازگشت "key lacks certificate data";
	حالت SSH_ERR_کلید_CERT_UNKNOWN_TYPE:
		بازگشت "unknown/unsupported certificate type";
	حالت SSH_ERR_کلید_CERT_INVALID_SIGN_کلید:
		بازگشت "invalid certificate signing key";
	حالت SSH_ERR_کلید_INVALID_EC_مقدار:
		بازگشت "invalid elliptic curve value";
	حالت SSH_ERR_SIGNATURE_INVALID:
		بازگشت "incorrect signature";
	حالت SSH_ERR_LIBCRYPTO_ERROR:
		پیام = ssherr_libcrypto();
		بازگشت پیام != پوچ ? پیام : "error in libcrypto";
	حالت SSH_ERR_INTERNAL_CRYPTO_ERROR:
		بازگشت "cryptographic operation failed";
	حالت SSH_ERR_UNEXPECTED_TRAILING_DATA:
		بازگشت "unexpected bytes remain after decoding";
	حالت SSH_ERR_SYSTEM_ERROR:
		بازگشت strerror(errno);
	حالت SSH_ERR_کلید_CERT_INVALID:
		بازگشت "invalid certificate";
	حالت SSH_ERR_AGENT_COMMUNICATION:
		بازگشت "communication with agent failed";
	حالت SSH_ERR_AGENT_FAILURE:
		بازگشت "agent refused operation";
	حالت SSH_ERR_DH_GEX_OUT_OF_RANGE:
		بازگشت "DH GEX group out of range";
	حالت SSH_ERR_DISCONNECTED:
		بازگشت "disconnected";
	حالت SSH_ERR_MAC_INVALID:
		بازگشت "message authentication code incorrect";
	حالت SSH_ERR_NO_CIPHER_ALG_MATCH:
		بازگشت "no matching cipher found";
	حالت SSH_ERR_NO_MAC_ALG_MATCH:
		بازگشت "no matching MAC found";
	حالت SSH_ERR_NO_COMPRESS_ALG_MATCH:
		بازگشت "no matching compression method found";
	حالت SSH_ERR_NO_KEX_ALG_MATCH:
		بازگشت "no matching key exchange method found";
	حالت SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		بازگشت "no matching host key type found";
	حالت SSH_ERR_PROTOCOL_MISMATCH:
		بازگشت "protocol version mismatch";
	حالت SSH_ERR_NO_PROTOCOL_VERSION:
		بازگشت "could not read protocol version";
	حالت SSH_ERR_NO_HOSTKEY_LOADED:
		بازگشت "could not load host key";
	حالت SSH_ERR_NEED_REKEY:
		بازگشت "rekeying not supported by peer";
	حالت SSH_ERR_PASSPHRASE_TOO_SHORT:
		بازگشت "passphrase is too short (minimum five characters)";
	حالت SSH_ERR_FILE_CHANGED:
		بازگشت "file changed while reading";
	حالت SSH_ERR_کلید_UNKNOWN_CIPHER:
		بازگشت "key encrypted using unsupported cipher";
	حالت SSH_ERR_کلید_WRONG_PASSPHRASE:
		بازگشت "incorrect passphrase supplied to decrypt private key";
	حالت SSH_ERR_کلید_BAD_PERMISSIONS:
		بازگشت "bad permissions";
	حالت SSH_ERR_کلید_CERT_MISMATCH:
		بازگشت "certificate does not match key";
	حالت SSH_ERR_کلید_NOT_FOUND:
		بازگشت "key not found";
	حالت SSH_ERR_AGENT_NOT_PRESENT:
		بازگشت "agent not present";
	حالت SSH_ERR_AGENT_NO_IDENTITIES:
		بازگشت "agent contains no identities";
	حالت SSH_ERR_BUFFER_READ_ONLY:
		بازگشت "internal error: buffer is read-only";
	حالت SSH_ERR_KRL_BAD_MAGIC:
		بازگشت "KRL file has invalid magic number";
	حالت SSH_ERR_کلید_REVOKED:
		بازگشت "Key is revoked";
	حالت SSH_ERR_CONN_CLOSED:
		بازگشت "Connection closed";
	حالت SSH_ERR_CONN_TIMEOUT:
		بازگشت "Connection timed out";
	حالت SSH_ERR_CONN_CORRUPT:
		بازگشت "Connection corrupted";
	حالت SSH_ERR_PROTOCOL_ERROR:
		بازگشت "Protocol error";
	حالت SSH_ERR_کلید_LENGTH:
		بازگشت "Invalid key length";
	حالت SSH_ERR_عدد_TOO_LARGE:
		بازگشت "number is too large";
	حالت SSH_ERR_کلید_ALG_UNSUPPORTED:
		بازگشت "key algorithm not supported";
	حالت SSH_ERR_SIGN_ALG_UNSUPPORTED:
		بازگشت "signature algorithm not supported";
	حالت SSH_ERR_FEATURE_UNSUPPORTED:
		بازگشت "requested feature not supported";
	حالت SSH_ERR_DEVICE_NOT_FOUND:
		بازگشت "device not found";
	پیشفرض:
		بازگشت "unknown error";
	}
}
