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

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ "ssherr.h"

സ്ഥിരം അക്ഷരം *
ssh_err(പൂർണ്ണസംഖ്യ n)
{
	സ്ഥിരം അക്ഷരം *സന്ദേശം = ശൂന്യ;

	തിരഞ്ഞെടുപ്പ് (n) {
	അവസ്ഥ SSH_ERR_SUCCESS:
		തിരികെ "success";
	അവസ്ഥ SSH_ERR_INTERNAL_ERROR:
		തിരികെ "unexpected internal error";
	അവസ്ഥ SSH_ERR_ALLOC_FAIL:
		തിരികെ "memory allocation failed";
	അവസ്ഥ SSH_ERR_MESSAGE_INCOMPLETE:
		തിരികെ "incomplete message";
	അവസ്ഥ SSH_ERR_INVALID_FORMAT:
		തിരികെ "invalid format";
	അവസ്ഥ SSH_ERR_BIGNUM_IS_NEGATIVE:
		തിരികെ "bignum is negative";
	അവസ്ഥ SSH_ERR_STRING_TOO_LARGE:
		തിരികെ "string is too large";
	അവസ്ഥ SSH_ERR_BIGNUM_TOO_LARGE:
		തിരികെ "bignum is too large";
	അവസ്ഥ SSH_ERR_ECPOINT_TOO_LARGE:
		തിരികെ "elliptic curve point is too large";
	അവസ്ഥ SSH_ERR_NO_BUFFER_SPACE:
		തിരികെ "insufficient buffer space";
	അവസ്ഥ SSH_ERR_INVALID_ARGUMENT:
		തിരികെ "invalid argument";
	അവസ്ഥ SSH_ERR_താക്കോൽ_BITS_MISMATCH:
		തിരികെ "key bits do not match";
	അവസ്ഥ SSH_ERR_EC_CURVE_INVALID:
		തിരികെ "invalid elliptic curve";
	അവസ്ഥ SSH_ERR_താക്കോൽ_TYPE_MISMATCH:
		തിരികെ "key type does not match";
	അവസ്ഥ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN:
		തിരികെ "unknown or unsupported key type";
	അവസ്ഥ SSH_ERR_EC_CURVE_MISMATCH:
		തിരികെ "elliptic curve does not match";
	അവസ്ഥ SSH_ERR_EXPECTED_CERT:
		തിരികെ "plain key provided where certificate required";
	അവസ്ഥ SSH_ERR_താക്കോൽ_LACKS_CERTBLOB:
		തിരികെ "key lacks certificate data";
	അവസ്ഥ SSH_ERR_താക്കോൽ_CERT_UNKNOWN_TYPE:
		തിരികെ "unknown/unsupported certificate type";
	അവസ്ഥ SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ:
		തിരികെ "invalid certificate signing key";
	അവസ്ഥ SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം:
		തിരികെ "invalid elliptic curve value";
	അവസ്ഥ SSH_ERR_SIGNATURE_INVALID:
		തിരികെ "incorrect signature";
	അവസ്ഥ SSH_ERR_LIBCRYPTO_ERROR:
		സന്ദേശം = ssherr_libcrypto();
		തിരികെ സന്ദേശം != ശൂന്യ ? സന്ദേശം : "error in libcrypto";
	അവസ്ഥ SSH_ERR_INTERNAL_CRYPTO_ERROR:
		തിരികെ "cryptographic operation failed";
	അവസ്ഥ SSH_ERR_UNEXPECTED_TRAILING_DATA:
		തിരികെ "unexpected bytes remain after decoding";
	അവസ്ഥ SSH_ERR_SYSTEM_ERROR:
		തിരികെ strerror(errno);
	അവസ്ഥ SSH_ERR_താക്കോൽ_CERT_INVALID:
		തിരികെ "invalid certificate";
	അവസ്ഥ SSH_ERR_AGENT_COMMUNICATION:
		തിരികെ "communication with agent failed";
	അവസ്ഥ SSH_ERR_AGENT_FAILURE:
		തിരികെ "agent refused operation";
	അവസ്ഥ SSH_ERR_DH_GEX_OUT_OF_RANGE:
		തിരികെ "DH GEX group out of range";
	അവസ്ഥ SSH_ERR_DISCONNECTED:
		തിരികെ "disconnected";
	അവസ്ഥ SSH_ERR_MAC_INVALID:
		തിരികെ "message authentication code incorrect";
	അവസ്ഥ SSH_ERR_NO_CIPHER_ALG_MATCH:
		തിരികെ "no matching cipher found";
	അവസ്ഥ SSH_ERR_NO_MAC_ALG_MATCH:
		തിരികെ "no matching MAC found";
	അവസ്ഥ SSH_ERR_NO_COMPRESS_ALG_MATCH:
		തിരികെ "no matching compression method found";
	അവസ്ഥ SSH_ERR_NO_KEX_ALG_MATCH:
		തിരികെ "no matching key exchange method found";
	അവസ്ഥ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		തിരികെ "no matching host key type found";
	അവസ്ഥ SSH_ERR_PROTOCOL_MISMATCH:
		തിരികെ "protocol version mismatch";
	അവസ്ഥ SSH_ERR_NO_PROTOCOL_VERSION:
		തിരികെ "could not read protocol version";
	അവസ്ഥ SSH_ERR_NO_HOSTKEY_LOADED:
		തിരികെ "could not load host key";
	അവസ്ഥ SSH_ERR_NEED_REKEY:
		തിരികെ "rekeying not supported by peer";
	അവസ്ഥ SSH_ERR_PASSPHRASE_TOO_SHORT:
		തിരികെ "passphrase is too short (minimum five characters)";
	അവസ്ഥ SSH_ERR_FILE_CHANGED:
		തിരികെ "file changed while reading";
	അവസ്ഥ SSH_ERR_താക്കോൽ_UNKNOWN_CIPHER:
		തിരികെ "key encrypted using unsupported cipher";
	അവസ്ഥ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE:
		തിരികെ "incorrect passphrase supplied to decrypt private key";
	അവസ്ഥ SSH_ERR_താക്കോൽ_BAD_PERMISSIONS:
		തിരികെ "bad permissions";
	അവസ്ഥ SSH_ERR_താക്കോൽ_CERT_MISMATCH:
		തിരികെ "certificate does not match key";
	അവസ്ഥ SSH_ERR_താക്കോൽ_NOT_FOUND:
		തിരികെ "key not found";
	അവസ്ഥ SSH_ERR_AGENT_NOT_PRESENT:
		തിരികെ "agent not present";
	അവസ്ഥ SSH_ERR_AGENT_NO_IDENTITIES:
		തിരികെ "agent contains no identities";
	അവസ്ഥ SSH_ERR_BUFFER_READ_ONLY:
		തിരികെ "internal error: buffer is read-only";
	അവസ്ഥ SSH_ERR_KRL_BAD_MAGIC:
		തിരികെ "KRL file has invalid magic number";
	അവസ്ഥ SSH_ERR_താക്കോൽ_REVOKED:
		തിരികെ "Key is revoked";
	അവസ്ഥ SSH_ERR_CONN_CLOSED:
		തിരികെ "Connection closed";
	അവസ്ഥ SSH_ERR_CONN_TIMEOUT:
		തിരികെ "Connection timed out";
	അവസ്ഥ SSH_ERR_CONN_CORRUPT:
		തിരികെ "Connection corrupted";
	അവസ്ഥ SSH_ERR_PROTOCOL_ERROR:
		തിരികെ "Protocol error";
	അവസ്ഥ SSH_ERR_താക്കോൽ_LENGTH:
		തിരികെ "Invalid key length";
	അവസ്ഥ SSH_ERR_സംഖ്യ_TOO_LARGE:
		തിരികെ "number is too large";
	അവസ്ഥ SSH_ERR_താക്കോൽ_ALG_UNSUPPORTED:
		തിരികെ "key algorithm not supported";
	അവസ്ഥ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		തിരികെ "signature algorithm not supported";
	അവസ്ഥ SSH_ERR_FEATURE_UNSUPPORTED:
		തിരികെ "requested feature not supported";
	അവസ്ഥ SSH_ERR_DEVICE_NOT_FOUND:
		തിരികെ "device not found";
	സ്ഥിരസ്ഥിതി:
		തിരികെ "unknown error";
	}
}
