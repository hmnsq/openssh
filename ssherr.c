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
ssh_err(số_nguyên n)
{
	const char *msg = NULL;

	switch (n) {
	case SSH_ERR_SUCCESS:
		trả_về "success";
	case SSH_ERR_INTERNAL_ERROR:
		trả_về "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		trả_về "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		trả_về "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		trả_về "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		trả_về "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		trả_về "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		trả_về "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		trả_về "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		trả_về "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		trả_về "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		trả_về "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		trả_về "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		trả_về "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		trả_về "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		trả_về "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		trả_về "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		trả_về "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		trả_về "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		trả_về "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		trả_về "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		trả_về "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		trả_về msg != NULL ? msg : "error in libcrypto";
	case SSH_ERR_INTERNAL_CRYPTO_ERROR:
		trả_về "cryptographic operation failed";
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		trả_về "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		trả_về strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		trả_về "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		trả_về "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		trả_về "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		trả_về "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		trả_về "disconnected";
	case SSH_ERR_MAC_INVALID:
		trả_về "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		trả_về "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		trả_về "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		trả_về "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		trả_về "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		trả_về "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		trả_về "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		trả_về "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		trả_về "could not load host key";
	case SSH_ERR_NEED_REKEY:
		trả_về "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		trả_về "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		trả_về "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		trả_về "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		trả_về "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		trả_về "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		trả_về "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		trả_về "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		trả_về "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		trả_về "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		trả_về "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		trả_về "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		trả_về "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		trả_về "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		trả_về "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		trả_về "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		trả_về "Protocol error";
	case SSH_ERR_KEY_LENGTH:
		trả_về "Invalid key length";
	case SSH_ERR_NUMBER_TOO_LARGE:
		trả_về "number is too large";
	case SSH_ERR_KEY_ALG_UNSUPPORTED:
		trả_về "key algorithm not supported";
	case SSH_ERR_SIGN_ALG_UNSUPPORTED:
		trả_về "signature algorithm not supported";
	case SSH_ERR_FEATURE_UNSUPPORTED:
		trả_về "requested feature not supported";
	case SSH_ERR_DEVICE_NOT_FOUND:
		trả_về "device not found";
	default:
		trả_về "unknown error";
	}
}
