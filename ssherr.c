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
		पटिनिवत्त "success";
	पक्ष SSH_ERR_INTERNAL_ERROR:
		पटिनिवत्त "unexpected internal error";
	पक्ष SSH_ERR_ALLOC_FAIL:
		पटिनिवत्त "memory allocation failed";
	पक्ष SSH_ERR_MESSAGE_INCOMPLETE:
		पटिनिवत्त "incomplete message";
	पक्ष SSH_ERR_INVALID_FORMAT:
		पटिनिवत्त "invalid format";
	पक्ष SSH_ERR_BIGNUM_IS_NEGATIVE:
		पटिनिवत्त "bignum is negative";
	पक्ष SSH_ERR_STRING_TOO_LARGE:
		पटिनिवत्त "string is too large";
	पक्ष SSH_ERR_BIGNUM_TOO_LARGE:
		पटिनिवत्त "bignum is too large";
	पक्ष SSH_ERR_ECPOINT_TOO_LARGE:
		पटिनिवत्त "elliptic curve point is too large";
	पक्ष SSH_ERR_NO_BUFFER_SPACE:
		पटिनिवत्त "insufficient buffer space";
	पक्ष SSH_ERR_INVALID_ARGUMENT:
		पटिनिवत्त "invalid argument";
	पक्ष SSH_ERR_कुञ्चिका_BITS_MISMATCH:
		पटिनिवत्त "key bits do not match";
	पक्ष SSH_ERR_EC_CURVE_INVALID:
		पटिनिवत्त "invalid elliptic curve";
	पक्ष SSH_ERR_कुञ्चिका_TYPE_MISMATCH:
		पटिनिवत्त "key type does not match";
	पक्ष SSH_ERR_कुञ्चिका_TYPE_UNKNOWN:
		पटिनिवत्त "unknown or unsupported key type";
	पक्ष SSH_ERR_EC_CURVE_MISMATCH:
		पटिनिवत्त "elliptic curve does not match";
	पक्ष SSH_ERR_EXPECTED_CERT:
		पटिनिवत्त "plain key provided where certificate required";
	पक्ष SSH_ERR_कुञ्चिका_LACKS_CERTBLOB:
		पटिनिवत्त "key lacks certificate data";
	पक्ष SSH_ERR_कुञ्चिका_CERT_UNKNOWN_TYPE:
		पटिनिवत्त "unknown/unsupported certificate type";
	पक्ष SSH_ERR_कुञ्चिका_CERT_INVALID_SIGN_कुञ्चिका:
		पटिनिवत्त "invalid certificate signing key";
	पक्ष SSH_ERR_कुञ्चिका_INVALID_EC_मानम्:
		पटिनिवत्त "invalid elliptic curve value";
	पक्ष SSH_ERR_SIGNATURE_INVALID:
		पटिनिवत्त "incorrect signature";
	पक्ष SSH_ERR_LIBCRYPTO_ERROR:
		सन्देशः = ssherr_libcrypto();
		पटिनिवत्त सन्देशः != रिक्त ? सन्देशः : "error in libcrypto";
	पक्ष SSH_ERR_INTERNAL_CRYPTO_ERROR:
		पटिनिवत्त "cryptographic operation failed";
	पक्ष SSH_ERR_UNEXPECTED_TRAILING_DATA:
		पटिनिवत्त "unexpected bytes remain after decoding";
	पक्ष SSH_ERR_SYSTEM_ERROR:
		पटिनिवत्त strerror(errno);
	पक्ष SSH_ERR_कुञ्चिका_CERT_INVALID:
		पटिनिवत्त "invalid certificate";
	पक्ष SSH_ERR_AGENT_COMMUNICATION:
		पटिनिवत्त "communication with agent failed";
	पक्ष SSH_ERR_AGENT_FAILURE:
		पटिनिवत्त "agent refused operation";
	पक्ष SSH_ERR_DH_GEX_OUT_OF_RANGE:
		पटिनिवत्त "DH GEX group out of range";
	पक्ष SSH_ERR_DISCONNECTED:
		पटिनिवत्त "disconnected";
	पक्ष SSH_ERR_MAC_INVALID:
		पटिनिवत्त "message authentication code incorrect";
	पक्ष SSH_ERR_NO_CIPHER_ALG_MATCH:
		पटिनिवत्त "no matching cipher found";
	पक्ष SSH_ERR_NO_MAC_ALG_MATCH:
		पटिनिवत्त "no matching MAC found";
	पक्ष SSH_ERR_NO_COMPRESS_ALG_MATCH:
		पटिनिवत्त "no matching compression method found";
	पक्ष SSH_ERR_NO_KEX_ALG_MATCH:
		पटिनिवत्त "no matching key exchange method found";
	पक्ष SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		पटिनिवत्त "no matching host key type found";
	पक्ष SSH_ERR_PROTOCOL_MISMATCH:
		पटिनिवत्त "protocol version mismatch";
	पक्ष SSH_ERR_NO_PROTOCOL_VERSION:
		पटिनिवत्त "could not read protocol version";
	पक्ष SSH_ERR_NO_HOSTKEY_LOADED:
		पटिनिवत्त "could not load host key";
	पक्ष SSH_ERR_NEED_REKEY:
		पटिनिवत्त "rekeying not supported by peer";
	पक्ष SSH_ERR_PASSPHRASE_TOO_SHORT:
		पटिनिवत्त "passphrase is too short (minimum five characters)";
	पक्ष SSH_ERR_FILE_CHANGED:
		पटिनिवत्त "file changed while reading";
	पक्ष SSH_ERR_कुञ्चिका_UNKNOWN_CIPHER:
		पटिनिवत्त "key encrypted using unsupported cipher";
	पक्ष SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE:
		पटिनिवत्त "incorrect passphrase supplied to decrypt private key";
	पक्ष SSH_ERR_कुञ्चिका_BAD_PERMISSIONS:
		पटिनिवत्त "bad permissions";
	पक्ष SSH_ERR_कुञ्चिका_CERT_MISMATCH:
		पटिनिवत्त "certificate does not match key";
	पक्ष SSH_ERR_कुञ्चिका_NOT_FOUND:
		पटिनिवत्त "key not found";
	पक्ष SSH_ERR_AGENT_NOT_PRESENT:
		पटिनिवत्त "agent not present";
	पक्ष SSH_ERR_AGENT_NO_IDENTITIES:
		पटिनिवत्त "agent contains no identities";
	पक्ष SSH_ERR_BUFFER_READ_ONLY:
		पटिनिवत्त "internal error: buffer is read-only";
	पक्ष SSH_ERR_KRL_BAD_MAGIC:
		पटिनिवत्त "KRL file has invalid magic number";
	पक्ष SSH_ERR_कुञ्चिका_REVOKED:
		पटिनिवत्त "Key is revoked";
	पक्ष SSH_ERR_CONN_CLOSED:
		पटिनिवत्त "Connection closed";
	पक्ष SSH_ERR_CONN_TIMEOUT:
		पटिनिवत्त "Connection timed out";
	पक्ष SSH_ERR_CONN_CORRUPT:
		पटिनिवत्त "Connection corrupted";
	पक्ष SSH_ERR_PROTOCOL_ERROR:
		पटिनिवत्त "Protocol error";
	पक्ष SSH_ERR_कुञ्चिका_LENGTH:
		पटिनिवत्त "Invalid key length";
	पक्ष SSH_ERR_सङ्ख्या_TOO_LARGE:
		पटिनिवत्त "number is too large";
	पक्ष SSH_ERR_कुञ्चिका_ALG_UNSUPPORTED:
		पटिनिवत्त "key algorithm not supported";
	पक्ष SSH_ERR_SIGN_ALG_UNSUPPORTED:
		पटिनिवत्त "signature algorithm not supported";
	पक्ष SSH_ERR_FEATURE_UNSUPPORTED:
		पटिनिवत्त "requested feature not supported";
	पक्ष SSH_ERR_DEVICE_NOT_FOUND:
		पटिनिवत्त "device not found";
	स्वभाव:
		पटिनिवत्त "unknown error";
	}
}
