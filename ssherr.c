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
ssh_err(정수 n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		반환 "success";
	case SSH_ERR_INTERNAL_ERROR:
		반환 "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		반환 "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		반환 "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		반환 "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		반환 "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		반환 "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		반환 "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		반환 "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		반환 "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		반환 "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		반환 "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		반환 "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		반환 "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		반환 "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		반환 "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		반환 "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		반환 "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		반환 "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		반환 "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		반환 "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		반환 "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		반환 msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		반환 "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		반환 "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		반환 strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		반환 "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		반환 "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		반환 "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		반환 "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		반환 "disconnected";
	case SSH_ERR_MAC_INVALID:
		반환 "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		반환 "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		반환 "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		반환 "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		반환 "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		반환 "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		반환 "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		반환 "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		반환 "could not load host key";
	case SSH_ERR_NEED_REKEY:
		반환 "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		반환 "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		반환 "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		반환 "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		반환 "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		반환 "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		반환 "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		반환 "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		반환 "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		반환 "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		반환 "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		반환 "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		반환 "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		반환 "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		반환 "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		반환 "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		반환 "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		반환 "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		반환 "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		반환 "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		반환 "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		반환 "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		반환 "device not found";
	default:
		반환 "unknown error";
	}
}
