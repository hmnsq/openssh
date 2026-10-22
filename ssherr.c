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

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ "ssherr.h"

ধ্রুৱ ৱর্ণ *
ssh_err(পূর্ণাঙ্ক n)
{
	ধ্রুৱ ৱর্ণ *বাৰ্তা = রিক্ত;

	ৱিকল্প (n) {
	পক্ষ SSH_ERR_SUCCESS:
		ঘূৰাই "success";
	পক্ষ SSH_ERR_INTERNAL_ERROR:
		ঘূৰাই "unexpected internal error";
	পক্ষ SSH_ERR_ALLOC_FAIL:
		ঘূৰাই "memory allocation failed";
	পক্ষ SSH_ERR_MESSAGE_INCOMPLETE:
		ঘূৰাই "incomplete message";
	পক্ষ SSH_ERR_INVALID_FORMAT:
		ঘূৰাই "invalid format";
	পক্ষ SSH_ERR_BIGNUM_IS_NEGATIVE:
		ঘূৰাই "bignum is negative";
	পক্ষ SSH_ERR_STRING_TOO_LARGE:
		ঘূৰাই "string is too large";
	পক্ষ SSH_ERR_BIGNUM_TOO_LARGE:
		ঘূৰাই "bignum is too large";
	পক্ষ SSH_ERR_ECPOINT_TOO_LARGE:
		ঘূৰাই "elliptic curve point is too large";
	পক্ষ SSH_ERR_NO_BUFFER_SPACE:
		ঘূৰাই "insufficient buffer space";
	পক্ষ SSH_ERR_INVALID_ARGUMENT:
		ঘূৰাই "invalid argument";
	পক্ষ SSH_ERR_চাবি_BITS_MISMATCH:
		ঘূৰাই "key bits do not match";
	পক্ষ SSH_ERR_EC_CURVE_INVALID:
		ঘূৰাই "invalid elliptic curve";
	পক্ষ SSH_ERR_চাবি_TYPE_MISMATCH:
		ঘূৰাই "key type does not match";
	পক্ষ SSH_ERR_চাবি_TYPE_UNKNOWN:
		ঘূৰাই "unknown or unsupported key type";
	পক্ষ SSH_ERR_EC_CURVE_MISMATCH:
		ঘূৰাই "elliptic curve does not match";
	পক্ষ SSH_ERR_EXPECTED_CERT:
		ঘূৰাই "plain key provided where certificate required";
	পক্ষ SSH_ERR_চাবি_LACKS_CERTBLOB:
		ঘূৰাই "key lacks certificate data";
	পক্ষ SSH_ERR_চাবি_CERT_UNKNOWN_TYPE:
		ঘূৰাই "unknown/unsupported certificate type";
	পক্ষ SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি:
		ঘূৰাই "invalid certificate signing key";
	পক্ষ SSH_ERR_চাবি_INVALID_EC_মান:
		ঘূৰাই "invalid elliptic curve value";
	পক্ষ SSH_ERR_SIGNATURE_INVALID:
		ঘূৰাই "incorrect signature";
	পক্ষ SSH_ERR_LIBCRYPTO_ERROR:
		বাৰ্তা = ssherr_libcrypto();
		ঘূৰাই বাৰ্তা != রিক্ত ? বাৰ্তা : "error in libcrypto";
	পক্ষ SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ঘূৰাই "cryptographic operation failed";
	পক্ষ SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ঘূৰাই "unexpected bytes remain after decoding";
	পক্ষ SSH_ERR_SYSTEM_ERROR:
		ঘূৰাই strerror(errno);
	পক্ষ SSH_ERR_চাবি_CERT_INVALID:
		ঘূৰাই "invalid certificate";
	পক্ষ SSH_ERR_AGENT_COMMUNICATION:
		ঘূৰাই "communication with agent failed";
	পক্ষ SSH_ERR_AGENT_FAILURE:
		ঘূৰাই "agent refused operation";
	পক্ষ SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ঘূৰাই "DH GEX group out of range";
	পক্ষ SSH_ERR_DISCONNECTED:
		ঘূৰাই "disconnected";
	পক্ষ SSH_ERR_MAC_INVALID:
		ঘূৰাই "message authentication code incorrect";
	পক্ষ SSH_ERR_NO_CIPHER_ALG_MATCH:
		ঘূৰাই "no matching cipher found";
	পক্ষ SSH_ERR_NO_MAC_ALG_MATCH:
		ঘূৰাই "no matching MAC found";
	পক্ষ SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ঘূৰাই "no matching compression method found";
	পক্ষ SSH_ERR_NO_KEX_ALG_MATCH:
		ঘূৰাই "no matching key exchange method found";
	পক্ষ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ঘূৰাই "no matching host key type found";
	পক্ষ SSH_ERR_PROTOCOL_MISMATCH:
		ঘূৰাই "protocol version mismatch";
	পক্ষ SSH_ERR_NO_PROTOCOL_VERSION:
		ঘূৰাই "could not read protocol version";
	পক্ষ SSH_ERR_NO_HOSTKEY_LOADED:
		ঘূৰাই "could not load host key";
	পক্ষ SSH_ERR_NEED_REKEY:
		ঘূৰাই "rekeying not supported by peer";
	পক্ষ SSH_ERR_PASSPHRASE_TOO_SHORT:
		ঘূৰাই "passphrase is too short (minimum five characters)";
	পক্ষ SSH_ERR_FILE_CHANGED:
		ঘূৰাই "file changed while reading";
	পক্ষ SSH_ERR_চাবি_UNKNOWN_CIPHER:
		ঘূৰাই "key encrypted using unsupported cipher";
	পক্ষ SSH_ERR_চাবি_WRONG_PASSPHRASE:
		ঘূৰাই "incorrect passphrase supplied to decrypt private key";
	পক্ষ SSH_ERR_চাবি_BAD_PERMISSIONS:
		ঘূৰাই "bad permissions";
	পক্ষ SSH_ERR_চাবি_CERT_MISMATCH:
		ঘূৰাই "certificate does not match key";
	পক্ষ SSH_ERR_চাবি_NOT_FOUND:
		ঘূৰাই "key not found";
	পক্ষ SSH_ERR_AGENT_NOT_PRESENT:
		ঘূৰাই "agent not present";
	পক্ষ SSH_ERR_AGENT_NO_IDENTITIES:
		ঘূৰাই "agent contains no identities";
	পক্ষ SSH_ERR_BUFFER_READ_ONLY:
		ঘূৰাই "internal error: buffer is read-only";
	পক্ষ SSH_ERR_KRL_BAD_MAGIC:
		ঘূৰাই "KRL file has invalid magic number";
	পক্ষ SSH_ERR_চাবি_REVOKED:
		ঘূৰাই "Key is revoked";
	পক্ষ SSH_ERR_CONN_CLOSED:
		ঘূৰাই "Connection closed";
	পক্ষ SSH_ERR_CONN_TIMEOUT:
		ঘূৰাই "Connection timed out";
	পক্ষ SSH_ERR_CONN_CORRUPT:
		ঘূৰাই "Connection corrupted";
	পক্ষ SSH_ERR_PROTOCOL_ERROR:
		ঘূৰাই "Protocol error";
	পক্ষ SSH_ERR_চাবি_LENGTH:
		ঘূৰাই "Invalid key length";
	পক্ষ SSH_ERR_সংখ্যা_TOO_LARGE:
		ঘূৰাই "number is too large";
	পক্ষ SSH_ERR_চাবি_ALG_UNSUPPORTED:
		ঘূৰাই "key algorithm not supported";
	পক্ষ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ঘূৰাই "signature algorithm not supported";
	পক্ষ SSH_ERR_FEATURE_UNSUPPORTED:
		ঘূৰাই "requested feature not supported";
	পক্ষ SSH_ERR_DEVICE_NOT_FOUND:
		ঘূৰাই "device not found";
	স্ৱভাৱ:
		ঘূৰাই "unknown error";
	}
}
