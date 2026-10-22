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
ssh_err(цео n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		врати "success";
	case SSH_ERR_INTERNAL_ERROR:
		врати "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		врати "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		врати "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		врати "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		врати "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		врати "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		врати "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		врати "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		врати "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		врати "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		врати "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		врати "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		врати "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		врати "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		врати "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		врати "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		врати "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		врати "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		врати "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		врати "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		врати "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		врати msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		врати "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		врати "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		врати strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		врати "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		врати "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		врати "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		врати "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		врати "disconnected";
	case SSH_ERR_MAC_INVALID:
		врати "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		врати "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		врати "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		врати "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		врати "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		врати "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		врати "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		врати "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		врати "could not load host key";
	case SSH_ERR_NEED_REKEY:
		врати "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		врати "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		врати "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		врати "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		врати "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		врати "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		врати "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		врати "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		врати "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		врати "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		врати "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		врати "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		врати "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		врати "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		врати "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		врати "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		врати "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		врати "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		врати "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		врати "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		врати "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		врати "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		врати "device not found";
	default:
		врати "unknown error";
	}
}
