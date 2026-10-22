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

#समावेश <errno.h>
#समावेश <string.h>
#समावेश "ssherr.h"

स्थिर अक्षर *
ssh_err(पूर्णांक n)
{
	स्थिर अक्षर *संदेश = शून्य;

	चयन (n) {
	हाल SSH_ERR_SUCCESS:
		वापस "success";
	हाल SSH_ERR_INTERNAL_ERROR:
		वापस "unexpected internal error";
	हाल SSH_ERR_ALLOC_FAIL:
		वापस "memory allocation failed";
	हाल SSH_ERR_MESSAGE_INCOMPLETE:
		वापस "incomplete message";
	हाल SSH_ERR_INVALID_FORMAT:
		वापस "invalid format";
	हाल SSH_ERR_BIGNUM_IS_NEGATIVE:
		वापस "bignum is negative";
	हाल SSH_ERR_STRING_TOO_LARGE:
		वापस "string is too large";
	हाल SSH_ERR_BIGNUM_TOO_LARGE:
		वापस "bignum is too large";
	हाल SSH_ERR_ECPOINT_TOO_LARGE:
		वापस "elliptic curve point is too large";
	हाल SSH_ERR_NO_बफर_SPACE:
		वापस "insufficient buffer space";
	हाल SSH_ERR_INVALID_ARGUMENT:
		वापस "invalid argument";
	हाल SSH_ERR_कुंजी_BITS_MISMATCH:
		वापस "key bits do not match";
	हाल SSH_ERR_EC_CURVE_INVALID:
		वापस "invalid elliptic curve";
	हाल SSH_ERR_कुंजी_TYPE_MISMATCH:
		वापस "key type does not match";
	हाल SSH_ERR_कुंजी_TYPE_UNKNOWN:
		वापस "unknown or unsupported key type";
	हाल SSH_ERR_EC_CURVE_MISMATCH:
		वापस "elliptic curve does not match";
	हाल SSH_ERR_EXPECTED_CERT:
		वापस "plain key provided where certificate required";
	हाल SSH_ERR_कुंजी_LACKS_CERTBLOB:
		वापस "key lacks certificate data";
	हाल SSH_ERR_कुंजी_CERT_UNKNOWN_TYPE:
		वापस "unknown/unsupported certificate type";
	हाल SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी:
		वापस "invalid certificate signing key";
	हाल SSH_ERR_कुंजी_INVALID_EC_मूल्य:
		वापस "invalid elliptic curve value";
	हाल SSH_ERR_SIGNATURE_INVALID:
		वापस "incorrect signature";
	हाल SSH_ERR_LIBCRYPTO_ERROR:
		संदेश = ssherr_libcrypto();
		वापस संदेश != शून्य ? संदेश : "error in libcrypto";
	हाल SSH_ERR_INTERNAL_CRYPTO_ERROR:
		वापस "cryptographic operation failed";
	हाल SSH_ERR_UNEXPECTED_TRAILING_तथ्य:
		वापस "unexpected bytes remain after decoding";
	हाल SSH_ERR_SYSTEM_ERROR:
		वापस म_त्रुटि(त्रुटि_सं);
	हाल SSH_ERR_कुंजी_CERT_INVALID:
		वापस "invalid certificate";
	हाल SSH_ERR_AGENT_COMMUNICATION:
		वापस "communication with agent failed";
	हाल SSH_ERR_AGENT_FAILURE:
		वापस "agent refused operation";
	हाल SSH_ERR_DH_GEX_OUT_OF_RANGE:
		वापस "DH GEX group out of range";
	हाल SSH_ERR_DISCONNECTED:
		वापस "disconnected";
	हाल SSH_ERR_MAC_INVALID:
		वापस "message authentication code incorrect";
	हाल SSH_ERR_NO_CIPHER_ALG_MATCH:
		वापस "no matching cipher found";
	हाल SSH_ERR_NO_MAC_ALG_MATCH:
		वापस "no matching MAC found";
	हाल SSH_ERR_NO_COMPRESS_ALG_MATCH:
		वापस "no matching compression method found";
	हाल SSH_ERR_NO_KEX_ALG_MATCH:
		वापस "no matching key exchange method found";
	हाल SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		वापस "no matching host key type found";
	हाल SSH_ERR_PROTOCOL_MISMATCH:
		वापस "protocol version mismatch";
	हाल SSH_ERR_NO_PROTOCOL_VERSION:
		वापस "could not read protocol version";
	हाल SSH_ERR_NO_HOSTKEY_LOADED:
		वापस "could not load host key";
	हाल SSH_ERR_NEED_REKEY:
		वापस "rekeying not supported by peer";
	हाल SSH_ERR_PASSPHRASE_TOO_SHORT:
		वापस "passphrase is too short (minimum five characters)";
	हाल SSH_ERR_FILE_CHANGED:
		वापस "file changed while reading";
	हाल SSH_ERR_कुंजी_UNKNOWN_CIPHER:
		वापस "key encrypted using unsupported cipher";
	हाल SSH_ERR_कुंजी_WRONG_PASSPHRASE:
		वापस "incorrect passphrase supplied to decrypt private key";
	हाल SSH_ERR_कुंजी_BAD_PERMISSIONS:
		वापस "bad permissions";
	हाल SSH_ERR_कुंजी_CERT_MISMATCH:
		वापस "certificate does not match key";
	हाल SSH_ERR_कुंजी_NOT_FOUND:
		वापस "key not found";
	हाल SSH_ERR_AGENT_NOT_PRESENT:
		वापस "agent not present";
	हाल SSH_ERR_AGENT_NO_IDENTITIES:
		वापस "agent contains no identities";
	हाल SSH_ERR_बफर_READ_ONLY:
		वापस "internal error: buffer is read-only";
	हाल SSH_ERR_KRL_BAD_MAGIC:
		वापस "KRL file has invalid magic number";
	हाल SSH_ERR_कुंजी_REVOKED:
		वापस "Key is revoked";
	हाल SSH_ERR_CONN_CLOSED:
		वापस "Connection closed";
	हाल SSH_ERR_CONN_TIMEOUT:
		वापस "Connection timed out";
	हाल SSH_ERR_CONN_CORRUPT:
		वापस "Connection corrupted";
	हाल SSH_ERR_PROTOCOL_ERROR:
		वापस "Protocol error";
	हाल SSH_ERR_कुंजी_लंबाई:
		वापस "Invalid key length";
	हाल SSH_ERR_संख्या_TOO_LARGE:
		वापस "number is too large";
	हाल SSH_ERR_कुंजी_ALG_UNSUPPORTED:
		वापस "key algorithm not supported";
	हाल SSH_ERR_SIGN_ALG_UNSUPPORTED:
		वापस "signature algorithm not supported";
	हाल SSH_ERR_FEATURE_UNSUPPORTED:
		वापस "requested feature not supported";
	हाल SSH_ERR_DEVICE_NOT_FOUND:
		वापस "device not found";
	शेष:
		वापस "unknown error";
	}
}
