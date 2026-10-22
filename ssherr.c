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
		戻る "success";
	case SSH_ERR_INTERNAL_ERROR:
		戻る "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		戻る "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		戻る "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		戻る "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		戻る "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		戻る "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		戻る "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		戻る "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		戻る "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		戻る "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		戻る "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		戻る "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		戻る "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		戻る "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		戻る "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		戻る "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		戻る "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		戻る "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		戻る "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		戻る "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		戻る "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		戻る msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		戻る "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		戻る "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		戻る strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		戻る "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		戻る "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		戻る "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		戻る "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		戻る "disconnected";
	case SSH_ERR_MAC_INVALID:
		戻る "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		戻る "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		戻る "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		戻る "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		戻る "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		戻る "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		戻る "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		戻る "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		戻る "could not load host key";
	case SSH_ERR_NEED_REKEY:
		戻る "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		戻る "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		戻る "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		戻る "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		戻る "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		戻る "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		戻る "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		戻る "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		戻る "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		戻る "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		戻る "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		戻る "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		戻る "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		戻る "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		戻る "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		戻る "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		戻る "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		戻る "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		戻る "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		戻る "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		戻る "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		戻る "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		戻る "device not found";
	default:
		戻る "unknown error";
	}
}
