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

#ضمن <errno.h>
#ضمن <string.h>
#ضمن "ssherr.h"

ثابت حرف *
ssh_err(صحيح n)
{
	ثابت حرف *رسالة = عدم;

	بدل (n) {
	حالة SSH_ERR_SUCCESS:
		إرجاع "success";
	حالة SSH_ERR_INTERNAL_ERROR:
		إرجاع "unexpected internal error";
	حالة SSH_ERR_ALLOC_FAIL:
		إرجاع "memory allocation failed";
	حالة SSH_ERR_MESSAGE_INCOMPLETE:
		إرجاع "incomplete message";
	حالة SSH_ERR_INVALID_FORMAT:
		إرجاع "invalid format";
	حالة SSH_ERR_BIGNUM_IS_NEGATIVE:
		إرجاع "bignum is negative";
	حالة SSH_ERR_STRING_TOO_LARGE:
		إرجاع "string is too large";
	حالة SSH_ERR_BIGNUM_TOO_LARGE:
		إرجاع "bignum is too large";
	حالة SSH_ERR_ECPOINT_TOO_LARGE:
		إرجاع "elliptic curve point is too large";
	حالة SSH_ERR_NO_BUFFER_SPACE:
		إرجاع "insufficient buffer space";
	حالة SSH_ERR_INVALID_ARGUMENT:
		إرجاع "invalid argument";
	حالة SSH_ERR_مفتاح_BITS_MISMATCH:
		إرجاع "key bits do not match";
	حالة SSH_ERR_EC_CURVE_INVALID:
		إرجاع "invalid elliptic curve";
	حالة SSH_ERR_مفتاح_TYPE_MISMATCH:
		إرجاع "key type does not match";
	حالة SSH_ERR_مفتاح_TYPE_UNKNOWN:
		إرجاع "unknown or unsupported key type";
	حالة SSH_ERR_EC_CURVE_MISMATCH:
		إرجاع "elliptic curve does not match";
	حالة SSH_ERR_EXPECTED_CERT:
		إرجاع "plain key provided where certificate required";
	حالة SSH_ERR_مفتاح_LACKS_CERTBLOB:
		إرجاع "key lacks certificate data";
	حالة SSH_ERR_مفتاح_CERT_UNKNOWN_TYPE:
		إرجاع "unknown/unsupported certificate type";
	حالة SSH_ERR_مفتاح_CERT_INVALID_SIGN_مفتاح:
		إرجاع "invalid certificate signing key";
	حالة SSH_ERR_مفتاح_INVALID_EC_قيمة:
		إرجاع "invalid elliptic curve value";
	حالة SSH_ERR_SIGNATURE_INVALID:
		إرجاع "incorrect signature";
	حالة SSH_ERR_LIBCRYPTO_ERROR:
		رسالة = ssherr_libcrypto();
		إرجاع رسالة != عدم ? رسالة : "error in libcrypto";
	حالة SSH_ERR_INTERNAL_CRYPTO_ERROR:
		إرجاع "cryptographic operation failed";
	حالة SSH_ERR_UNEXPECTED_TRAILING_DATA:
		إرجاع "unexpected bytes remain after decoding";
	حالة SSH_ERR_SYSTEM_ERROR:
		إرجاع strerror(errno);
	حالة SSH_ERR_مفتاح_CERT_INVALID:
		إرجاع "invalid certificate";
	حالة SSH_ERR_AGENT_COMMUNICATION:
		إرجاع "communication with agent failed";
	حالة SSH_ERR_AGENT_FAILURE:
		إرجاع "agent refused operation";
	حالة SSH_ERR_DH_GEX_OUT_OF_RANGE:
		إرجاع "DH GEX group out of range";
	حالة SSH_ERR_DISCONNECTED:
		إرجاع "disconnected";
	حالة SSH_ERR_MAC_INVALID:
		إرجاع "message authentication code incorrect";
	حالة SSH_ERR_NO_CIPHER_ALG_MATCH:
		إرجاع "no matching cipher found";
	حالة SSH_ERR_NO_MAC_ALG_MATCH:
		إرجاع "no matching MAC found";
	حالة SSH_ERR_NO_COMPRESS_ALG_MATCH:
		إرجاع "no matching compression method found";
	حالة SSH_ERR_NO_KEX_ALG_MATCH:
		إرجاع "no matching key exchange method found";
	حالة SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		إرجاع "no matching host key type found";
	حالة SSH_ERR_PROTOCOL_MISMATCH:
		إرجاع "protocol version mismatch";
	حالة SSH_ERR_NO_PROTOCOL_VERSION:
		إرجاع "could not read protocol version";
	حالة SSH_ERR_NO_HOSTKEY_LOADED:
		إرجاع "could not load host key";
	حالة SSH_ERR_NEED_REKEY:
		إرجاع "rekeying not supported by peer";
	حالة SSH_ERR_PASSPHRASE_TOO_SHORT:
		إرجاع "passphrase is too short (minimum five characters)";
	حالة SSH_ERR_FILE_CHANGED:
		إرجاع "file changed while reading";
	حالة SSH_ERR_مفتاح_UNKNOWN_CIPHER:
		إرجاع "key encrypted using unsupported cipher";
	حالة SSH_ERR_مفتاح_WRONG_PASSPHRASE:
		إرجاع "incorrect passphrase supplied to decrypt private key";
	حالة SSH_ERR_مفتاح_BAD_PERMISSIONS:
		إرجاع "bad permissions";
	حالة SSH_ERR_مفتاح_CERT_MISMATCH:
		إرجاع "certificate does not match key";
	حالة SSH_ERR_مفتاح_NOT_FOUND:
		إرجاع "key not found";
	حالة SSH_ERR_AGENT_NOT_PRESENT:
		إرجاع "agent not present";
	حالة SSH_ERR_AGENT_NO_IDENTITIES:
		إرجاع "agent contains no identities";
	حالة SSH_ERR_BUFFER_READ_ONLY:
		إرجاع "internal error: buffer is read-only";
	حالة SSH_ERR_KRL_BAD_MAGIC:
		إرجاع "KRL file has invalid magic number";
	حالة SSH_ERR_مفتاح_REVOKED:
		إرجاع "Key is revoked";
	حالة SSH_ERR_CONN_CLOSED:
		إرجاع "Connection closed";
	حالة SSH_ERR_CONN_TIMEOUT:
		إرجاع "Connection timed out";
	حالة SSH_ERR_CONN_CORRUPT:
		إرجاع "Connection corrupted";
	حالة SSH_ERR_PROTOCOL_ERROR:
		إرجاع "Protocol error";
	حالة SSH_ERR_مفتاح_LENGTH:
		إرجاع "Invalid key length";
	حالة SSH_ERR_العدد_TOO_LARGE:
		إرجاع "number is too large";
	حالة SSH_ERR_مفتاح_ALG_UNSUPPORTED:
		إرجاع "key algorithm not supported";
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		إرجاع "signature algorithm not supported";
	حالة SSH_ERR_FEATURE_UNSUPPORTED:
		إرجاع "requested feature not supported";
	حالة SSH_ERR_DEVICE_NOT_FOUND:
		إرجاع "device not found";
	افتراضي:
		إرجاع "unknown error";
	}
}
