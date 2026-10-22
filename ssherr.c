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

const var_na *
ssh_err(จำนวนเต็ม n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		คืน "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		คืน "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		คืน "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		คืน "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		คืน "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		คืน "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		คืน "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		คืน "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		คืน "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		คืน "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		คืน "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		คืน "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		คืน "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		คืน "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		คืน "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		คืน "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		คืน "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		คืน "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		คืน "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		คืน "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		คืน "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		คืน "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		คืน msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		คืน "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		คืน "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		คืน strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		คืน "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		คืน "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		คืน "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		คืน "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		คืน "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		คืน "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		คืน "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		คืน "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		คืน "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		คืน "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		คืน "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		คืน "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		คืน "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		คืน "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		คืน "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		คืน "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		คืน "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		คืน "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		คืน "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		คืน "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		คืน "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		คืน "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		คืน "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		คืน "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		คืน "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		คืน "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		คืน "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		คืน "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		คืน "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		คืน "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		คืน "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		คืน "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		คืน "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		คืน "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		คืน "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		คืน "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		คืน "device not found";
	default:
		คืน "unknown error";
	}
}
