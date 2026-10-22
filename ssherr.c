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
ssh_err(ཧྲིལ n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		ལོག "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ལོག "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ལོག "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ལོག "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ལོག "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ལོག "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ལོག "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ལོག "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ལོག "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ལོག "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ལོག "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ལོག "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ལོག "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ལོག "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ལོག "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ལོག "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ལོག "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ལོག "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ལོག "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ལོག "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ལོག "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ལོག "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ལོག msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ལོག "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ལོག "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ལོག strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ལོག "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ལོག "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ལོག "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ལོག "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ལོག "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ལོག "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ལོག "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ལོག "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ལོག "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ལོག "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ལོག "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ལོག "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ལོག "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ལོག "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ལོག "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ལོག "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ལོག "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ལོག "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ལོག "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ལོག "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ལོག "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ལོག "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ལོག "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ལོག "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ལོག "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ལོག "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ལོག "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ལོག "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ལོག "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ལོག "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ལོག "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ལོག "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ལོག "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ལོག "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ལོག "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ལོག "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ལོག "device not found";
	default:
		ལོག "unknown error";
	}
}
