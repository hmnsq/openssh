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

#include <errno.h>
#include <string.h>
#include "ssherr.h"

const char *
ssh_err(цяло n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		върни "success";
	case SSH_ERR_INTERNAL_ERROR:
		върни "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		върни "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		върни "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		върни "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		върни "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		върни "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		върни "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		върни "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		върни "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		върни "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		върни "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		върни "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		върни "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		върни "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		върни "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		върни "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		върни "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		върни "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		върни "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		върни "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		върни "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		върни msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		върни "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		върни "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		върни strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		върни "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		върни "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		върни "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		върни "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		върни "disconnected";
	case SSH_ERR_MAC_INVALID:
		върни "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		върни "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		върни "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		върни "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		върни "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		върни "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		върни "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		върни "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		върни "could not load host key";
	case SSH_ERR_NEED_REKEY:
		върни "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		върни "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		върни "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		върни "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		върни "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		върни "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		върни "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		върни "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		върни "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		върни "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		върни "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		върни "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		върни "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		върни "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		върни "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		върни "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		върни "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		върни "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		върни "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		върни "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		върни "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		върни "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		върни "device not found";
	default:
		върни "unknown error";
	}
}
