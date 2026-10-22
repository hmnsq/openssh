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

अचर वर्ण *
ssh_err(पूर्णाङ्क n)
{
	अचर वर्ण *सन्देश = रिक्त;

	विकल्प (n) {
	पक्ष SSH_ERR_SUCCESS:
		फर्काऊ "success";
	पक्ष SSH_ERR_INTERNAL_ERROR:
		फर्काऊ "unexpected internal error";
	पक्ष SSH_ERR_ALLOC_FAIL:
		फर्काऊ "memory allocation failed";
	पक्ष SSH_ERR_MESSAGE_INCOMPLETE:
		फर्काऊ "incomplete message";
	पक्ष SSH_ERR_INVALID_FORMAT:
		फर्काऊ "invalid format";
	पक्ष SSH_ERR_BIGNUM_IS_NEGATIVE:
		फर्काऊ "bignum is negative";
	पक्ष SSH_ERR_STRING_TOO_LARGE:
		फर्काऊ "string is too large";
	पक्ष SSH_ERR_BIGNUM_TOO_LARGE:
		फर्काऊ "bignum is too large";
	पक्ष SSH_ERR_ECPOINT_TOO_LARGE:
		फर्काऊ "elliptic curve point is too large";
	पक्ष SSH_ERR_NO_BUFFER_SPACE:
		फर्काऊ "insufficient buffer space";
	पक्ष SSH_ERR_INVALID_ARGUMENT:
		फर्काऊ "invalid argument";
	पक्ष SSH_ERR_साँचो_BITS_MISMATCH:
		फर्काऊ "key bits do not match";
	पक्ष SSH_ERR_EC_CURVE_INVALID:
		फर्काऊ "invalid elliptic curve";
	पक्ष SSH_ERR_साँचो_TYPE_MISMATCH:
		फर्काऊ "key type does not match";
	पक्ष SSH_ERR_साँचो_TYPE_UNKNOWN:
		फर्काऊ "unknown or unsupported key type";
	पक्ष SSH_ERR_EC_CURVE_MISMATCH:
		फर्काऊ "elliptic curve does not match";
	पक्ष SSH_ERR_EXPECTED_CERT:
		फर्काऊ "plain key provided where certificate required";
	पक्ष SSH_ERR_साँचो_LACKS_CERTBLOB:
		फर्काऊ "key lacks certificate data";
	पक्ष SSH_ERR_साँचो_CERT_UNKNOWN_TYPE:
		फर्काऊ "unknown/unsupported certificate type";
	पक्ष SSH_ERR_साँचो_CERT_INVALID_SIGN_साँचो:
		फर्काऊ "invalid certificate signing key";
	पक्ष SSH_ERR_साँचो_INVALID_EC_मान:
		फर्काऊ "invalid elliptic curve value";
	पक्ष SSH_ERR_SIGNATURE_INVALID:
		फर्काऊ "incorrect signature";
	पक्ष SSH_ERR_LIBCRYPTO_ERROR:
		सन्देश = ssherr_libcrypto();
		फर्काऊ सन्देश != रिक्त ? सन्देश : "error in libcrypto";
	पक्ष SSH_ERR_INTERNAL_CRYPTO_ERROR:
		फर्काऊ "cryptographic operation failed";
	पक्ष SSH_ERR_UNEXPECTED_TRAILING_DATA:
		फर्काऊ "unexpected bytes remain after decoding";
	पक्ष SSH_ERR_SYSTEM_ERROR:
		फर्काऊ म_त्रुटि(त्रुटि_सं);
	पक्ष SSH_ERR_साँचो_CERT_INVALID:
		फर्काऊ "invalid certificate";
	पक्ष SSH_ERR_AGENT_COMMUNICATION:
		फर्काऊ "communication with agent failed";
	पक्ष SSH_ERR_AGENT_FAILURE:
		फर्काऊ "agent refused operation";
	पक्ष SSH_ERR_DH_GEX_OUT_OF_RANGE:
		फर्काऊ "DH GEX group out of range";
	पक्ष SSH_ERR_DISCONNECTED:
		फर्काऊ "disconnected";
	पक्ष SSH_ERR_MAC_INVALID:
		फर्काऊ "message authentication code incorrect";
	पक्ष SSH_ERR_NO_CIPHER_ALG_MATCH:
		फर्काऊ "no matching cipher found";
	पक्ष SSH_ERR_NO_MAC_ALG_MATCH:
		फर्काऊ "no matching MAC found";
	पक्ष SSH_ERR_NO_COMPRESS_ALG_MATCH:
		फर्काऊ "no matching compression method found";
	पक्ष SSH_ERR_NO_KEX_ALG_MATCH:
		फर्काऊ "no matching key exchange method found";
	पक्ष SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		फर्काऊ "no matching host key type found";
	पक्ष SSH_ERR_PROTOCOL_MISMATCH:
		फर्काऊ "protocol version mismatch";
	पक्ष SSH_ERR_NO_PROTOCOL_VERSION:
		फर्काऊ "could not read protocol version";
	पक्ष SSH_ERR_NO_HOSTKEY_LOADED:
		फर्काऊ "could not load host key";
	पक्ष SSH_ERR_NEED_REKEY:
		फर्काऊ "rekeying not supported by peer";
	पक्ष SSH_ERR_PASSPHRASE_TOO_SHORT:
		फर्काऊ "passphrase is too short (minimum five characters)";
	पक्ष SSH_ERR_FILE_CHANGED:
		फर्काऊ "file changed while reading";
	पक्ष SSH_ERR_साँचो_UNKNOWN_CIPHER:
		फर्काऊ "key encrypted using unsupported cipher";
	पक्ष SSH_ERR_साँचो_WRONG_PASSPHRASE:
		फर्काऊ "incorrect passphrase supplied to decrypt private key";
	पक्ष SSH_ERR_साँचो_BAD_PERMISSIONS:
		फर्काऊ "bad permissions";
	पक्ष SSH_ERR_साँचो_CERT_MISMATCH:
		फर्काऊ "certificate does not match key";
	पक्ष SSH_ERR_साँचो_NOT_FOUND:
		फर्काऊ "key not found";
	पक्ष SSH_ERR_AGENT_NOT_PRESENT:
		फर्काऊ "agent not present";
	पक्ष SSH_ERR_AGENT_NO_IDENTITIES:
		फर्काऊ "agent contains no identities";
	पक्ष SSH_ERR_BUFFER_READ_ONLY:
		फर्काऊ "internal error: buffer is read-only";
	पक्ष SSH_ERR_KRL_BAD_MAGIC:
		फर्काऊ "KRL file has invalid magic number";
	पक्ष SSH_ERR_साँचो_REVOKED:
		फर्काऊ "Key is revoked";
	पक्ष SSH_ERR_CONN_CLOSED:
		फर्काऊ "Connection closed";
	पक्ष SSH_ERR_CONN_TIMEOUT:
		फर्काऊ "Connection timed out";
	पक्ष SSH_ERR_CONN_CORRUPT:
		फर्काऊ "Connection corrupted";
	पक्ष SSH_ERR_PROTOCOL_ERROR:
		फर्काऊ "Protocol error";
	पक्ष SSH_ERR_साँचो_LENGTH:
		फर्काऊ "Invalid key length";
	पक्ष SSH_ERR_सङ्ख्या_TOO_LARGE:
		फर्काऊ "number is too large";
	पक्ष SSH_ERR_साँचो_ALG_UNSUPPORTED:
		फर्काऊ "key algorithm not supported";
	पक्ष SSH_ERR_SIGN_ALG_UNSUPPORTED:
		फर्काऊ "signature algorithm not supported";
	पक्ष SSH_ERR_FEATURE_UNSUPPORTED:
		फर्काऊ "requested feature not supported";
	पक्ष SSH_ERR_DEVICE_NOT_FOUND:
		फर्काऊ "device not found";
	स्वभाव:
		फर्काऊ "unknown error";
	}
}
