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
ssh_err(整数 n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		返回 "success";
	case SSH_ERR_INTERNAL_ERROR:
		返回 "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		返回 "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		返回 "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		返回 "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		返回 "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		返回 "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		返回 "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		返回 "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		返回 "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		返回 "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		返回 "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		返回 "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		返回 "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		返回 "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		返回 "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		返回 "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		返回 "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		返回 "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		返回 "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		返回 "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		返回 "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		返回 msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		返回 "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		返回 "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		返回 strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		返回 "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		返回 "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		返回 "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		返回 "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		返回 "disconnected";
	case SSH_ERR_MAC_INVALID:
		返回 "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		返回 "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		返回 "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		返回 "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		返回 "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		返回 "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		返回 "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		返回 "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		返回 "could not load host key";
	case SSH_ERR_NEED_REKEY:
		返回 "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		返回 "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		返回 "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		返回 "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		返回 "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		返回 "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		返回 "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		返回 "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		返回 "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		返回 "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		返回 "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		返回 "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		返回 "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		返回 "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		返回 "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		返回 "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		返回 "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		返回 "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		返回 "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		返回 "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		返回 "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		返回 "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		返回 "device not found";
	default:
		返回 "unknown error";
	}
}
