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

ধ্রুব বর্ণ *
ssh_err(পূর্ণাঙ্ক n)
{
	ধ্রুব বর্ণ *বার্তা = রিক্ত;

	বিকল্প (n) {
	পক্ষ SSH_ERR_SUCCESS:
		প্রত্যাগম "success";
	পক্ষ SSH_ERR_INTERNAL_ERROR:
		প্রত্যাগম "unexpected internal error";
	পক্ষ SSH_ERR_ALLOC_FAIL:
		প্রত্যাগম "memory allocation failed";
	পক্ষ SSH_ERR_MESSAGE_INCOMPLETE:
		প্রত্যাগম "incomplete message";
	পক্ষ SSH_ERR_INVALID_FORMAT:
		প্রত্যাগম "invalid format";
	পক্ষ SSH_ERR_BIGNUM_IS_NEGATIVE:
		প্রত্যাগম "bignum is negative";
	পক্ষ SSH_ERR_STRING_TOO_LARGE:
		প্রত্যাগম "string is too large";
	পক্ষ SSH_ERR_BIGNUM_TOO_LARGE:
		প্রত্যাগম "bignum is too large";
	পক্ষ SSH_ERR_ECPOINT_TOO_LARGE:
		প্রত্যাগম "elliptic curve point is too large";
	পক্ষ SSH_ERR_NO_BUFFER_SPACE:
		প্রত্যাগম "insufficient buffer space";
	পক্ষ SSH_ERR_INVALID_ARGUMENT:
		প্রত্যাগম "invalid argument";
	পক্ষ SSH_ERR_চাবি_BITS_MISMATCH:
		প্রত্যাগম "key bits do not match";
	পক্ষ SSH_ERR_EC_CURVE_INVALID:
		প্রত্যাগম "invalid elliptic curve";
	পক্ষ SSH_ERR_চাবি_TYPE_MISMATCH:
		প্রত্যাগম "key type does not match";
	পক্ষ SSH_ERR_চাবি_TYPE_UNKNOWN:
		প্রত্যাগম "unknown or unsupported key type";
	পক্ষ SSH_ERR_EC_CURVE_MISMATCH:
		প্রত্যাগম "elliptic curve does not match";
	পক্ষ SSH_ERR_EXPECTED_CERT:
		প্রত্যাগম "plain key provided where certificate required";
	পক্ষ SSH_ERR_চাবি_LACKS_CERTBLOB:
		প্রত্যাগম "key lacks certificate data";
	পক্ষ SSH_ERR_চাবি_CERT_UNKNOWN_TYPE:
		প্রত্যাগম "unknown/unsupported certificate type";
	পক্ষ SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি:
		প্রত্যাগম "invalid certificate signing key";
	পক্ষ SSH_ERR_চাবি_INVALID_EC_মান:
		প্রত্যাগম "invalid elliptic curve value";
	পক্ষ SSH_ERR_SIGNATURE_INVALID:
		প্রত্যাগম "incorrect signature";
	পক্ষ SSH_ERR_LIBCRYPTO_ERROR:
		বার্তা = ssherr_libcrypto();
		প্রত্যাগম বার্তা != রিক্ত ? বার্তা : "error in libcrypto";
	পক্ষ SSH_ERR_INTERNAL_CRYPTO_ERROR:
		প্রত্যাগম "cryptographic operation failed";
	পক্ষ SSH_ERR_UNEXPECTED_TRAILING_DATA:
		প্রত্যাগম "unexpected bytes remain after decoding";
	পক্ষ SSH_ERR_SYSTEM_ERROR:
		প্রত্যাগম strerror(errno);
	পক্ষ SSH_ERR_চাবি_CERT_INVALID:
		প্রত্যাগম "invalid certificate";
	পক্ষ SSH_ERR_AGENT_COMMUNICATION:
		প্রত্যাগম "communication with agent failed";
	পক্ষ SSH_ERR_AGENT_FAILURE:
		প্রত্যাগম "agent refused operation";
	পক্ষ SSH_ERR_DH_GEX_OUT_OF_RANGE:
		প্রত্যাগম "DH GEX group out of range";
	পক্ষ SSH_ERR_DISCONNECTED:
		প্রত্যাগম "disconnected";
	পক্ষ SSH_ERR_MAC_INVALID:
		প্রত্যাগম "message authentication code incorrect";
	পক্ষ SSH_ERR_NO_CIPHER_ALG_MATCH:
		প্রত্যাগম "no matching cipher found";
	পক্ষ SSH_ERR_NO_MAC_ALG_MATCH:
		প্রত্যাগম "no matching MAC found";
	পক্ষ SSH_ERR_NO_COMPRESS_ALG_MATCH:
		প্রত্যাগম "no matching compression method found";
	পক্ষ SSH_ERR_NO_KEX_ALG_MATCH:
		প্রত্যাগম "no matching key exchange method found";
	পক্ষ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		প্রত্যাগম "no matching host key type found";
	পক্ষ SSH_ERR_PROTOCOL_MISMATCH:
		প্রত্যাগম "protocol version mismatch";
	পক্ষ SSH_ERR_NO_PROTOCOL_VERSION:
		প্রত্যাগম "could not read protocol version";
	পক্ষ SSH_ERR_NO_HOSTKEY_LOADED:
		প্রত্যাগম "could not load host key";
	পক্ষ SSH_ERR_NEED_REKEY:
		প্রত্যাগম "rekeying not supported by peer";
	পক্ষ SSH_ERR_PASSPHRASE_TOO_SHORT:
		প্রত্যাগম "passphrase is too short (minimum five characters)";
	পক্ষ SSH_ERR_FILE_CHANGED:
		প্রত্যাগম "file changed while reading";
	পক্ষ SSH_ERR_চাবি_UNKNOWN_CIPHER:
		প্রত্যাগম "key encrypted using unsupported cipher";
	পক্ষ SSH_ERR_চাবি_WRONG_PASSPHRASE:
		প্রত্যাগম "incorrect passphrase supplied to decrypt private key";
	পক্ষ SSH_ERR_চাবি_BAD_PERMISSIONS:
		প্রত্যাগম "bad permissions";
	পক্ষ SSH_ERR_চাবি_CERT_MISMATCH:
		প্রত্যাগম "certificate does not match key";
	পক্ষ SSH_ERR_চাবি_NOT_FOUND:
		প্রত্যাগম "key not found";
	পক্ষ SSH_ERR_AGENT_NOT_PRESENT:
		প্রত্যাগম "agent not present";
	পক্ষ SSH_ERR_AGENT_NO_IDENTITIES:
		প্রত্যাগম "agent contains no identities";
	পক্ষ SSH_ERR_BUFFER_READ_ONLY:
		প্রত্যাগম "internal error: buffer is read-only";
	পক্ষ SSH_ERR_KRL_BAD_MAGIC:
		প্রত্যাগম "KRL file has invalid magic number";
	পক্ষ SSH_ERR_চাবি_REVOKED:
		প্রত্যাগম "Key is revoked";
	পক্ষ SSH_ERR_CONN_CLOSED:
		প্রত্যাগম "Connection closed";
	পক্ষ SSH_ERR_CONN_TIMEOUT:
		প্রত্যাগম "Connection timed out";
	পক্ষ SSH_ERR_CONN_CORRUPT:
		প্রত্যাগম "Connection corrupted";
	পক্ষ SSH_ERR_PROTOCOL_ERROR:
		প্রত্যাগম "Protocol error";
	পক্ষ SSH_ERR_চাবি_LENGTH:
		প্রত্যাগম "Invalid key length";
	পক্ষ SSH_ERR_সংখ্যা_TOO_LARGE:
		প্রত্যাগম "number is too large";
	পক্ষ SSH_ERR_চাবি_ALG_UNSUPPORTED:
		প্রত্যাগম "key algorithm not supported";
	পক্ষ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		প্রত্যাগম "signature algorithm not supported";
	পক্ষ SSH_ERR_FEATURE_UNSUPPORTED:
		প্রত্যাগম "requested feature not supported";
	পক্ষ SSH_ERR_DEVICE_NOT_FOUND:
		প্রত্যাগম "device not found";
	স্বভাব:
		প্রত্যাগম "unknown error";
	}
}
