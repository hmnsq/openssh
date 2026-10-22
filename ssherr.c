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

स्थिरांक अक्षर *
ssh_err(पूर्णांक n)
{
	स्थिरांक अक्षर *संदेश = रिक्त;

	निवड (n) {
	स्थिती SSH_ERR_SUCCESS:
		परत "success";
	स्थिती SSH_ERR_INTERNAL_ERROR:
		परत "unexpected internal error";
	स्थिती SSH_ERR_ALLOC_FAIL:
		परत "memory allocation failed";
	स्थिती SSH_ERR_MESSAGE_INCOMPLETE:
		परत "incomplete message";
	स्थिती SSH_ERR_INVALID_FORMAT:
		परत "invalid format";
	स्थिती SSH_ERR_BIGNUM_IS_NEGATIVE:
		परत "bignum is negative";
	स्थिती SSH_ERR_STRING_TOO_LARGE:
		परत "string is too large";
	स्थिती SSH_ERR_BIGNUM_TOO_LARGE:
		परत "bignum is too large";
	स्थिती SSH_ERR_ECPOINT_TOO_LARGE:
		परत "elliptic curve point is too large";
	स्थिती SSH_ERR_NO_BUFFER_SPACE:
		परत "insufficient buffer space";
	स्थिती SSH_ERR_INVALID_ARGUMENT:
		परत "invalid argument";
	स्थिती SSH_ERR_किल्ली_BITS_MISMATCH:
		परत "key bits do not match";
	स्थिती SSH_ERR_EC_CURVE_INVALID:
		परत "invalid elliptic curve";
	स्थिती SSH_ERR_किल्ली_TYPE_MISMATCH:
		परत "key type does not match";
	स्थिती SSH_ERR_किल्ली_TYPE_UNKNOWN:
		परत "unknown or unsupported key type";
	स्थिती SSH_ERR_EC_CURVE_MISMATCH:
		परत "elliptic curve does not match";
	स्थिती SSH_ERR_EXPECTED_CERT:
		परत "plain key provided where certificate required";
	स्थिती SSH_ERR_किल्ली_LACKS_CERTBLOB:
		परत "key lacks certificate data";
	स्थिती SSH_ERR_किल्ली_CERT_UNKNOWN_TYPE:
		परत "unknown/unsupported certificate type";
	स्थिती SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली:
		परत "invalid certificate signing key";
	स्थिती SSH_ERR_किल्ली_INVALID_EC_मूल्य:
		परत "invalid elliptic curve value";
	स्थिती SSH_ERR_SIGNATURE_INVALID:
		परत "incorrect signature";
	स्थिती SSH_ERR_LIBCRYPTO_ERROR:
		संदेश = ssherr_libcrypto();
		परत संदेश != रिक्त ? संदेश : "error in libcrypto";
	स्थिती SSH_ERR_INTERNAL_CRYPTO_ERROR:
		परत "cryptographic operation failed";
	स्थिती SSH_ERR_UNEXPECTED_TRAILING_DATA:
		परत "unexpected bytes remain after decoding";
	स्थिती SSH_ERR_SYSTEM_ERROR:
		परत म_त्रुटि(त्रुटि_सं);
	स्थिती SSH_ERR_किल्ली_CERT_INVALID:
		परत "invalid certificate";
	स्थिती SSH_ERR_AGENT_COMMUNICATION:
		परत "communication with agent failed";
	स्थिती SSH_ERR_AGENT_FAILURE:
		परत "agent refused operation";
	स्थिती SSH_ERR_DH_GEX_OUT_OF_RANGE:
		परत "DH GEX group out of range";
	स्थिती SSH_ERR_DISCONNECTED:
		परत "disconnected";
	स्थिती SSH_ERR_MAC_INVALID:
		परत "message authentication code incorrect";
	स्थिती SSH_ERR_NO_CIPHER_ALG_MATCH:
		परत "no matching cipher found";
	स्थिती SSH_ERR_NO_MAC_ALG_MATCH:
		परत "no matching MAC found";
	स्थिती SSH_ERR_NO_COMPRESS_ALG_MATCH:
		परत "no matching compression method found";
	स्थिती SSH_ERR_NO_KEX_ALG_MATCH:
		परत "no matching key exchange method found";
	स्थिती SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		परत "no matching host key type found";
	स्थिती SSH_ERR_PROTOCOL_MISMATCH:
		परत "protocol version mismatch";
	स्थिती SSH_ERR_NO_PROTOCOL_VERSION:
		परत "could not read protocol version";
	स्थिती SSH_ERR_NO_HOSTKEY_LOADED:
		परत "could not load host key";
	स्थिती SSH_ERR_NEED_REKEY:
		परत "rekeying not supported by peer";
	स्थिती SSH_ERR_PASSPHRASE_TOO_SHORT:
		परत "passphrase is too short (minimum five characters)";
	स्थिती SSH_ERR_FILE_CHANGED:
		परत "file changed while reading";
	स्थिती SSH_ERR_किल्ली_UNKNOWN_CIPHER:
		परत "key encrypted using unsupported cipher";
	स्थिती SSH_ERR_किल्ली_WRONG_PASSPHRASE:
		परत "incorrect passphrase supplied to decrypt private key";
	स्थिती SSH_ERR_किल्ली_BAD_PERMISSIONS:
		परत "bad permissions";
	स्थिती SSH_ERR_किल्ली_CERT_MISMATCH:
		परत "certificate does not match key";
	स्थिती SSH_ERR_किल्ली_NOT_FOUND:
		परत "key not found";
	स्थिती SSH_ERR_AGENT_NOT_PRESENT:
		परत "agent not present";
	स्थिती SSH_ERR_AGENT_NO_IDENTITIES:
		परत "agent contains no identities";
	स्थिती SSH_ERR_BUFFER_READ_ONLY:
		परत "internal error: buffer is read-only";
	स्थिती SSH_ERR_KRL_BAD_MAGIC:
		परत "KRL file has invalid magic number";
	स्थिती SSH_ERR_किल्ली_REVOKED:
		परत "Key is revoked";
	स्थिती SSH_ERR_CONN_CLOSED:
		परत "Connection closed";
	स्थिती SSH_ERR_CONN_TIMEOUT:
		परत "Connection timed out";
	स्थिती SSH_ERR_CONN_CORRUPT:
		परत "Connection corrupted";
	स्थिती SSH_ERR_PROTOCOL_ERROR:
		परत "Protocol error";
	स्थिती SSH_ERR_किल्ली_LENGTH:
		परत "Invalid key length";
	स्थिती SSH_ERR_संख्या_TOO_LARGE:
		परत "number is too large";
	स्थिती SSH_ERR_किल्ली_ALG_UNSUPPORTED:
		परत "key algorithm not supported";
	स्थिती SSH_ERR_SIGN_ALG_UNSUPPORTED:
		परत "signature algorithm not supported";
	स्थिती SSH_ERR_FEATURE_UNSUPPORTED:
		परत "requested feature not supported";
	स्थिती SSH_ERR_DEVICE_NOT_FOUND:
		परत "device not found";
	पूर्वनिर्धारित:
		परत "unknown error";
	}
}
