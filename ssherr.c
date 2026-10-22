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

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব "ssherr.h"

ধ্রুবক অক্ষর *
ssh_err(পূর্ণসংখ্যা n)
{
	ধ্রুবক অক্ষর *বার্তা = ফাঁকা;

	নির্বাচন (n) {
	ক্ষেত্র SSH_ERR_SUCCESS:
		ফেরত "success";
	ক্ষেত্র SSH_ERR_INTERNAL_ERROR:
		ফেরত "unexpected internal error";
	ক্ষেত্র SSH_ERR_ALLOC_FAIL:
		ফেরত "memory allocation failed";
	ক্ষেত্র SSH_ERR_MESSAGE_INCOMPLETE:
		ফেরত "incomplete message";
	ক্ষেত্র SSH_ERR_INVALID_FORMAT:
		ফেরত "invalid format";
	ক্ষেত্র SSH_ERR_BIGNUM_IS_NEGATIVE:
		ফেরত "bignum is negative";
	ক্ষেত্র SSH_ERR_STRING_TOO_LARGE:
		ফেরত "string is too large";
	ক্ষেত্র SSH_ERR_BIGNUM_TOO_LARGE:
		ফেরত "bignum is too large";
	ক্ষেত্র SSH_ERR_ECPOINT_TOO_LARGE:
		ফেরত "elliptic curve point is too large";
	ক্ষেত্র SSH_ERR_NO_বাফার_SPACE:
		ফেরত "insufficient buffer space";
	ক্ষেত্র SSH_ERR_INVALID_ARGUMENT:
		ফেরত "invalid argument";
	ক্ষেত্র SSH_ERR_চাবি_BITS_MISMATCH:
		ফেরত "key bits do not match";
	ক্ষেত্র SSH_ERR_EC_CURVE_INVALID:
		ফেরত "invalid elliptic curve";
	ক্ষেত্র SSH_ERR_চাবি_TYPE_MISMATCH:
		ফেরত "key type does not match";
	ক্ষেত্র SSH_ERR_চাবি_TYPE_UNKNOWN:
		ফেরত "unknown or unsupported key type";
	ক্ষেত্র SSH_ERR_EC_CURVE_MISMATCH:
		ফেরত "elliptic curve does not match";
	ক্ষেত্র SSH_ERR_EXPECTED_CERT:
		ফেরত "plain key provided where certificate required";
	ক্ষেত্র SSH_ERR_চাবি_LACKS_CERTBLOB:
		ফেরত "key lacks certificate data";
	ক্ষেত্র SSH_ERR_চাবি_CERT_UNKNOWN_TYPE:
		ফেরত "unknown/unsupported certificate type";
	ক্ষেত্র SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি:
		ফেরত "invalid certificate signing key";
	ক্ষেত্র SSH_ERR_চাবি_INVALID_EC_মান:
		ফেরত "invalid elliptic curve value";
	ক্ষেত্র SSH_ERR_SIGNATURE_INVALID:
		ফেরত "incorrect signature";
	ক্ষেত্র SSH_ERR_LIBCRYPTO_ERROR:
		বার্তা = ssherr_libcrypto();
		ফেরত বার্তা != ফাঁকা ? বার্তা : "error in libcrypto";
	ক্ষেত্র SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ফেরত "cryptographic operation failed";
	ক্ষেত্র SSH_ERR_UNEXPECTED_TRAILING_তথ্য:
		ফেরত "unexpected bytes remain after decoding";
	ক্ষেত্র SSH_ERR_SYSTEM_ERROR:
		ফেরত strerror(errno);
	ক্ষেত্র SSH_ERR_চাবি_CERT_INVALID:
		ফেরত "invalid certificate";
	ক্ষেত্র SSH_ERR_AGENT_COMMUNICATION:
		ফেরত "communication with agent failed";
	ক্ষেত্র SSH_ERR_AGENT_FAILURE:
		ফেরত "agent refused operation";
	ক্ষেত্র SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ফেরত "DH GEX group out of range";
	ক্ষেত্র SSH_ERR_DISCONNECTED:
		ফেরত "disconnected";
	ক্ষেত্র SSH_ERR_MAC_INVALID:
		ফেরত "message authentication code incorrect";
	ক্ষেত্র SSH_ERR_NO_CIPHER_ALG_MATCH:
		ফেরত "no matching cipher found";
	ক্ষেত্র SSH_ERR_NO_MAC_ALG_MATCH:
		ফেরত "no matching MAC found";
	ক্ষেত্র SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ফেরত "no matching compression method found";
	ক্ষেত্র SSH_ERR_NO_KEX_ALG_MATCH:
		ফেরত "no matching key exchange method found";
	ক্ষেত্র SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ফেরত "no matching host key type found";
	ক্ষেত্র SSH_ERR_PROTOCOL_MISMATCH:
		ফেরত "protocol version mismatch";
	ক্ষেত্র SSH_ERR_NO_PROTOCOL_VERSION:
		ফেরত "could not read protocol version";
	ক্ষেত্র SSH_ERR_NO_HOSTKEY_LOADED:
		ফেরত "could not load host key";
	ক্ষেত্র SSH_ERR_NEED_REKEY:
		ফেরত "rekeying not supported by peer";
	ক্ষেত্র SSH_ERR_PASSPHRASE_TOO_SHORT:
		ফেরত "passphrase is too short (minimum five characters)";
	ক্ষেত্র SSH_ERR_FILE_CHANGED:
		ফেরত "file changed while reading";
	ক্ষেত্র SSH_ERR_চাবি_UNKNOWN_CIPHER:
		ফেরত "key encrypted using unsupported cipher";
	ক্ষেত্র SSH_ERR_চাবি_WRONG_PASSPHRASE:
		ফেরত "incorrect passphrase supplied to decrypt private key";
	ক্ষেত্র SSH_ERR_চাবি_BAD_PERMISSIONS:
		ফেরত "bad permissions";
	ক্ষেত্র SSH_ERR_চাবি_CERT_MISMATCH:
		ফেরত "certificate does not match key";
	ক্ষেত্র SSH_ERR_চাবি_NOT_FOUND:
		ফেরত "key not found";
	ক্ষেত্র SSH_ERR_AGENT_NOT_PRESENT:
		ফেরত "agent not present";
	ক্ষেত্র SSH_ERR_AGENT_NO_IDENTITIES:
		ফেরত "agent contains no identities";
	ক্ষেত্র SSH_ERR_বাফার_READ_ONLY:
		ফেরত "internal error: buffer is read-only";
	ক্ষেত্র SSH_ERR_KRL_BAD_MAGIC:
		ফেরত "KRL file has invalid magic number";
	ক্ষেত্র SSH_ERR_চাবি_REVOKED:
		ফেরত "Key is revoked";
	ক্ষেত্র SSH_ERR_CONN_CLOSED:
		ফেরত "Connection closed";
	ক্ষেত্র SSH_ERR_CONN_TIMEOUT:
		ফেরত "Connection timed out";
	ক্ষেত্র SSH_ERR_CONN_CORRUPT:
		ফেরত "Connection corrupted";
	ক্ষেত্র SSH_ERR_PROTOCOL_ERROR:
		ফেরত "Protocol error";
	ক্ষেত্র SSH_ERR_চাবি_দৈর্ঘ্য:
		ফেরত "Invalid key length";
	ক্ষেত্র SSH_ERR_সংখ্যা_TOO_LARGE:
		ফেরত "number is too large";
	ক্ষেত্র SSH_ERR_চাবি_ALG_UNSUPPORTED:
		ফেরত "key algorithm not supported";
	ক্ষেত্র SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ফেরত "signature algorithm not supported";
	ক্ষেত্র SSH_ERR_FEATURE_UNSUPPORTED:
		ফেরত "requested feature not supported";
	ক্ষেত্র SSH_ERR_DEVICE_NOT_FOUND:
		ফেরত "device not found";
	পূর্বনির্ধারিত:
		ফেরত "unknown error";
	}
}
