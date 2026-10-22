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

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव "ssherr.h"

ध्रुव वर्ण *
ssh_err(पूर्णाङ्क n)
{
	ध्रुव वर्ण *सन्देशः = रिक्त;

	विकल्प (n) {
	पक्ष SSH_ERR_SUCCESS:
		प्रत्यागम "success";
	पक्ष SSH_ERR_आन्तरिकम्_ERROR:
		प्रत्यागम "unexpected internal error";
	पक्ष SSH_ERR_ALLOC_FAIL:
		प्रत्यागम "memory allocation failed";
	पक्ष SSH_ERR_सन्देशः_INCOMPLETE:
		प्रत्यागम "incomplete message";
	पक्ष SSH_ERR_INVALID_FORMAT:
		प्रत्यागम "invalid format";
	पक्ष SSH_ERR_BIGNUM_IS_NEGATIVE:
		प्रत्यागम "bignum is negative";
	पक्ष SSH_ERR_STRING_TOO_LARGE:
		प्रत्यागम "string is too large";
	पक्ष SSH_ERR_BIGNUM_TOO_LARGE:
		प्रत्यागम "bignum is too large";
	पक्ष SSH_ERR_ECPOINT_TOO_LARGE:
		प्रत्यागम "elliptic curve point is too large";
	पक्ष SSH_ERR_NO_बफर_SPACE:
		प्रत्यागम "insufficient buffer space";
	पक्ष SSH_ERR_INVALID_तर्कः:
		प्रत्यागम "invalid argument";
	पक्ष SSH_ERR_कुञ्चिका_द्वयङ्काः_MISMATCH:
		प्रत्यागम "key bits do not match";
	पक्ष SSH_ERR_EC_वक्रम्_INVALID:
		प्रत्यागम "invalid elliptic curve";
	पक्ष SSH_ERR_कुञ्चिका_TYPE_MISMATCH:
		प्रत्यागम "key type does not match";
	पक्ष SSH_ERR_कुञ्चिका_TYPE_UNKNOWN:
		प्रत्यागम "unknown or unsupported key type";
	पक्ष SSH_ERR_EC_वक्रम्_MISMATCH:
		प्रत्यागम "elliptic curve does not match";
	पक्ष SSH_ERR_EXPECTED_CERT:
		प्रत्यागम "plain key provided where certificate required";
	पक्ष SSH_ERR_कुञ्चिका_LACKS_CERTBLOB:
		प्रत्यागम "key lacks certificate data";
	पक्ष SSH_ERR_कुञ्चिका_CERT_UNKNOWN_TYPE:
		प्रत्यागम "unknown/unsupported certificate type";
	पक्ष SSH_ERR_कुञ्चिका_CERT_INVALID_SIGN_कुञ्चिका:
		प्रत्यागम "invalid certificate signing key";
	पक्ष SSH_ERR_कुञ्चिका_INVALID_EC_मानम्:
		प्रत्यागम "invalid elliptic curve value";
	पक्ष SSH_ERR_SIGNATURE_INVALID:
		प्रत्यागम "incorrect signature";
	पक्ष SSH_ERR_LIBCRYPTO_ERROR:
		सन्देशः = ssherr_libcrypto();
		प्रत्यागम सन्देशः != रिक्त ? सन्देशः : "error in libcrypto";
	पक्ष SSH_ERR_आन्तरिकम्_CRYPTO_ERROR:
		प्रत्यागम "cryptographic operation failed";
	पक्ष SSH_ERR_UNEXPECTED_TRAILING_दत्त:
		प्रत्यागम "unexpected bytes remain after decoding";
	पक्ष SSH_ERR_SYSTEM_ERROR:
		प्रत्यागम strerror(errno);
	पक्ष SSH_ERR_कुञ्चिका_CERT_INVALID:
		प्रत्यागम "invalid certificate";
	पक्ष SSH_ERR_AGENT_COMMUNICATION:
		प्रत्यागम "communication with agent failed";
	पक्ष SSH_ERR_AGENT_FAILURE:
		प्रत्यागम "agent refused operation";
	पक्ष SSH_ERR_DH_GEX_बहिर्गमनम्_सम्बन्धि_RANGE:
		प्रत्यागम "DH GEX group out of range";
	पक्ष SSH_ERR_DISCONNECTED:
		प्रत्यागम "disconnected";
	पक्ष SSH_ERR_MAC_INVALID:
		प्रत्यागम "message authentication code incorrect";
	पक्ष SSH_ERR_NO_CIPHER_ALG_मेलनम्:
		प्रत्यागम "no matching cipher found";
	पक्ष SSH_ERR_NO_MAC_ALG_मेलनम्:
		प्रत्यागम "no matching MAC found";
	पक्ष SSH_ERR_NO_COMPRESS_ALG_मेलनम्:
		प्रत्यागम "no matching compression method found";
	पक्ष SSH_ERR_NO_KEX_ALG_मेलनम्:
		प्रत्यागम "no matching key exchange method found";
	पक्ष SSH_ERR_NO_HOSTKEY_ALG_मेलनम्:
		प्रत्यागम "no matching host key type found";
	पक्ष SSH_ERR_PROTOCOL_MISMATCH:
		प्रत्यागम "protocol version mismatch";
	पक्ष SSH_ERR_NO_PROTOCOL_संस्करणम्:
		प्रत्यागम "could not read protocol version";
	पक्ष SSH_ERR_NO_HOSTKEY_LOADED:
		प्रत्यागम "could not load host key";
	पक्ष SSH_ERR_NEED_REKEY:
		प्रत्यागम "rekeying not supported by peer";
	पक्ष SSH_ERR_PASSPHRASE_TOO_SHORT:
		प्रत्यागम "passphrase is too short (minimum five characters)";
	पक्ष SSH_ERR_FILE_परिवर्तितम्:
		प्रत्यागम "file changed while reading";
	पक्ष SSH_ERR_कुञ्चिका_UNKNOWN_CIPHER:
		प्रत्यागम "key encrypted using unsupported cipher";
	पक्ष SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE:
		प्रत्यागम "incorrect passphrase supplied to decrypt private key";
	पक्ष SSH_ERR_कुञ्चिका_BAD_PERMISSIONS:
		प्रत्यागम "bad permissions";
	पक्ष SSH_ERR_कुञ्चिका_CERT_MISMATCH:
		प्रत्यागम "certificate does not match key";
	पक्ष SSH_ERR_कुञ्चिका_NOT_प्राप्तम्:
		प्रत्यागम "key not found";
	पक्ष SSH_ERR_AGENT_NOT_PRESENT:
		प्रत्यागम "agent not present";
	पक्ष SSH_ERR_AGENT_NO_IDENTITIES:
		प्रत्यागम "agent contains no identities";
	पक्ष SSH_ERR_बफर_READ_ONLY:
		प्रत्यागम "internal error: buffer is read-only";
	पक्ष SSH_ERR_KRL_BAD_MAGIC:
		प्रत्यागम "KRL file has invalid magic number";
	पक्ष SSH_ERR_कुञ्चिका_REVOKED:
		प्रत्यागम "Key is revoked";
	पक्ष SSH_ERR_CONN_CLOSED:
		प्रत्यागम "Connection closed";
	पक्ष SSH_ERR_CONN_TIMEOUT:
		प्रत्यागम "Connection timed out";
	पक्ष SSH_ERR_CONN_CORRUPT:
		प्रत्यागम "Connection corrupted";
	पक्ष SSH_ERR_PROTOCOL_ERROR:
		प्रत्यागम "Protocol error";
	पक्ष SSH_ERR_कुञ्चिका_दीर्घता:
		प्रत्यागम "Invalid key length";
	पक्ष SSH_ERR_सङ्ख्या_TOO_LARGE:
		प्रत्यागम "number is too large";
	पक्ष SSH_ERR_कुञ्चिका_ALG_UNSUPPORTED:
		प्रत्यागम "key algorithm not supported";
	पक्ष SSH_ERR_SIGN_ALG_UNSUPPORTED:
		प्रत्यागम "signature algorithm not supported";
	पक्ष SSH_ERR_FEATURE_UNSUPPORTED:
		प्रत्यागम "requested feature not supported";
	पक्ष SSH_ERR_DEVICE_NOT_प्राप्तम्:
		प्रत्यागम "device not found";
	स्वभाव:
		प्रत्यागम "unknown error";
	}
}
