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

ثابت حرف *
ssh_err(صحیح n)
{
	ثابت حرف *پیغام = تہی;

	انتخاب (n) {
	حالت SSH_ERR_SUCCESS:
		واپس "success";
	حالت SSH_ERR_اندرونی_ERROR:
		واپس "unexpected internal error";
	حالت SSH_ERR_ALLOC_FAIL:
		واپس "memory allocation failed";
	حالت SSH_ERR_پیغام_INCOMPLETE:
		واپس "incomplete message";
	حالت SSH_ERR_INVALID_FORMAT:
		واپس "invalid format";
	حالت SSH_ERR_BIGNUM_IS_NEGATIVE:
		واپس "bignum is negative";
	حالت SSH_ERR_STRING_TOO_LARGE:
		واپس "string is too large";
	حالت SSH_ERR_BIGNUM_TOO_LARGE:
		واپس "bignum is too large";
	حالت SSH_ERR_ECPOINT_TOO_LARGE:
		واپس "elliptic curve point is too large";
	حالت SSH_ERR_NO_بفر_SPACE:
		واپس "insufficient buffer space";
	حالت SSH_ERR_INVALID_دلیل:
		واپس "invalid argument";
	حالت SSH_ERR_کلید_بٹ_MISMATCH:
		واپس "key bits do not match";
	حالت SSH_ERR_EC_خم_INVALID:
		واپس "invalid elliptic curve";
	حالت SSH_ERR_کلید_TYPE_MISMATCH:
		واپس "key type does not match";
	حالت SSH_ERR_کلید_TYPE_UNKNOWN:
		واپس "unknown or unsupported key type";
	حالت SSH_ERR_EC_خم_MISMATCH:
		واپس "elliptic curve does not match";
	حالت SSH_ERR_EXPECTED_CERT:
		واپس "plain key provided where certificate required";
	حالت SSH_ERR_کلید_LACKS_CERTBLOB:
		واپس "key lacks certificate data";
	حالت SSH_ERR_کلید_CERT_UNKNOWN_TYPE:
		واپس "unknown/unsupported certificate type";
	حالت SSH_ERR_کلید_CERT_INVALID_SIGN_کلید:
		واپس "invalid certificate signing key";
	حالت SSH_ERR_کلید_INVALID_EC_قدر:
		واپس "invalid elliptic curve value";
	حالت SSH_ERR_SIGNATURE_INVALID:
		واپس "incorrect signature";
	حالت SSH_ERR_LIBCRYPTO_ERROR:
		پیغام = ssherr_libcrypto();
		واپس پیغام != تہی ? پیغام : "error in libcrypto";
	حالت SSH_ERR_اندرونی_CRYPTO_ERROR:
		واپس "cryptographic operation failed";
	حالت SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا:
		واپس "unexpected bytes remain after decoding";
	حالت SSH_ERR_SYSTEM_ERROR:
		واپس strerror(errno);
	حالت SSH_ERR_کلید_CERT_INVALID:
		واپس "invalid certificate";
	حالت SSH_ERR_AGENT_COMMUNICATION:
		واپس "communication with agent failed";
	حالت SSH_ERR_AGENT_FAILURE:
		واپس "agent refused operation";
	حالت SSH_ERR_DH_GEX_برآمد_کا_RANGE:
		واپس "DH GEX group out of range";
	حالت SSH_ERR_DISCONNECTED:
		واپس "disconnected";
	حالت SSH_ERR_MAC_INVALID:
		واپس "message authentication code incorrect";
	حالت SSH_ERR_NO_CIPHER_ALG_مطابقت:
		واپس "no matching cipher found";
	حالت SSH_ERR_NO_MAC_ALG_مطابقت:
		واپس "no matching MAC found";
	حالت SSH_ERR_NO_COMPRESS_ALG_مطابقت:
		واپس "no matching compression method found";
	حالت SSH_ERR_NO_KEX_ALG_مطابقت:
		واپس "no matching key exchange method found";
	حالت SSH_ERR_NO_HOSTKEY_ALG_مطابقت:
		واپس "no matching host key type found";
	حالت SSH_ERR_PROTOCOL_MISMATCH:
		واپس "protocol version mismatch";
	حالت SSH_ERR_NO_PROTOCOL_نسخہ:
		واپس "could not read protocol version";
	حالت SSH_ERR_NO_HOSTKEY_LOADED:
		واپس "could not load host key";
	حالت SSH_ERR_NEED_REKEY:
		واپس "rekeying not supported by peer";
	حالت SSH_ERR_PASSPHRASE_TOO_SHORT:
		واپس "passphrase is too short (minimum five characters)";
	حالت SSH_ERR_FILE_بدلا:
		واپس "file changed while reading";
	حالت SSH_ERR_کلید_UNKNOWN_CIPHER:
		واپس "key encrypted using unsupported cipher";
	حالت SSH_ERR_کلید_WRONG_PASSPHRASE:
		واپس "incorrect passphrase supplied to decrypt private key";
	حالت SSH_ERR_کلید_BAD_PERMISSIONS:
		واپس "bad permissions";
	حالت SSH_ERR_کلید_CERT_MISMATCH:
		واپس "certificate does not match key";
	حالت SSH_ERR_کلید_NOT_ملا:
		واپس "key not found";
	حالت SSH_ERR_AGENT_NOT_PRESENT:
		واپس "agent not present";
	حالت SSH_ERR_AGENT_NO_IDENTITIES:
		واپس "agent contains no identities";
	حالت SSH_ERR_بفر_READ_ONLY:
		واپس "internal error: buffer is read-only";
	حالت SSH_ERR_KRL_BAD_MAGIC:
		واپس "KRL file has invalid magic number";
	حالت SSH_ERR_کلید_REVOKED:
		واپس "Key is revoked";
	حالت SSH_ERR_CONN_CLOSED:
		واپس "Connection closed";
	حالت SSH_ERR_CONN_TIMEOUT:
		واپس "Connection timed out";
	حالت SSH_ERR_CONN_CORRUPT:
		واپس "Connection corrupted";
	حالت SSH_ERR_PROTOCOL_ERROR:
		واپس "Protocol error";
	حالت SSH_ERR_کلید_لمبائی:
		واپس "Invalid key length";
	حالت SSH_ERR_نمبر_TOO_LARGE:
		واپس "number is too large";
	حالت SSH_ERR_کلید_ALG_UNSUPPORTED:
		واپس "key algorithm not supported";
	حالت SSH_ERR_SIGN_ALG_UNSUPPORTED:
		واپس "signature algorithm not supported";
	حالت SSH_ERR_FEATURE_UNSUPPORTED:
		واپس "requested feature not supported";
	حالت SSH_ERR_DEVICE_NOT_ملا:
		واپس "device not found";
	طےشدہ:
		واپس "unknown error";
	}
}
