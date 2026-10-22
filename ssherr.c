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
ssh_err(ціле n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		повернути "success";
	case SSH_ERR_INTERNAL_ERROR:
		повернути "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		повернути "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		повернути "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		повернути "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		повернути "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		повернути "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		повернути "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		повернути "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		повернути "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		повернути "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		повернути "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		повернути "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		повернути "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		повернути "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		повернути "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		повернути "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		повернути "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		повернути "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		повернути "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		повернути "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		повернути "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		повернути msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		повернути "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		повернути "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		повернути strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		повернути "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		повернути "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		повернути "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		повернути "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		повернути "disconnected";
	case SSH_ERR_MAC_INVALID:
		повернути "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		повернути "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		повернути "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		повернути "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		повернути "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		повернути "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		повернути "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		повернути "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		повернути "could not load host key";
	case SSH_ERR_NEED_REKEY:
		повернути "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		повернути "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		повернути "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		повернути "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		повернути "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		повернути "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		повернути "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		повернути "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		повернути "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		повернути "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		повернути "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		повернути "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		повернути "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		повернути "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		повернути "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		повернути "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		повернути "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		повернути "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		повернути "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		повернути "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		повернути "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		повернути "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		повернути "device not found";
	default:
		повернути "unknown error";
	}
}
