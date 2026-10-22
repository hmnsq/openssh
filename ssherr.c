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
ssh_err(целое n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		вернуть "success";
	case SSH_ERR_INTERNAL_ERROR:
		вернуть "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		вернуть "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		вернуть "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		вернуть "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		вернуть "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		вернуть "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		вернуть "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		вернуть "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		вернуть "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		вернуть "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		вернуть "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		вернуть "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		вернуть "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		вернуть "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		вернуть "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		вернуть "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		вернуть "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		вернуть "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		вернуть "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		вернуть "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		вернуть "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		вернуть msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		вернуть "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		вернуть "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		вернуть strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		вернуть "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		вернуть "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		вернуть "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		вернуть "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		вернуть "disconnected";
	case SSH_ERR_MAC_INVALID:
		вернуть "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		вернуть "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		вернуть "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		вернуть "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		вернуть "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		вернуть "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		вернуть "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		вернуть "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		вернуть "could not load host key";
	case SSH_ERR_NEED_REKEY:
		вернуть "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		вернуть "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		вернуть "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		вернуть "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		вернуть "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		вернуть "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		вернуть "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		вернуть "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		вернуть "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		вернуть "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		вернуть "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		вернуть "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		вернуть "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		вернуть "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		вернуть "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		вернуть "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		вернуть "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		вернуть "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		вернуть "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		вернуть "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		вернуть "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		вернуть "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		вернуть "device not found";
	default:
		вернуть "unknown error";
	}
}
