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
ssh_err(puur_naa_nka n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		ꦮꦭꦶ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ꦮꦭꦶ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ꦮꦭꦶ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ꦮꦭꦶ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ꦮꦭꦶ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ꦮꦭꦶ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ꦮꦭꦶ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ꦮꦭꦶ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ꦮꦭꦶ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ꦮꦭꦶ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ꦮꦭꦶ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ꦮꦭꦶ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ꦮꦭꦶ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ꦮꦭꦶ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ꦮꦭꦶ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ꦮꦭꦶ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ꦮꦭꦶ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ꦮꦭꦶ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ꦮꦭꦶ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ꦮꦭꦶ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ꦮꦭꦶ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ꦮꦭꦶ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ꦮꦭꦶ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ꦮꦭꦶ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ꦮꦭꦶ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ꦮꦭꦶ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ꦮꦭꦶ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ꦮꦭꦶ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ꦮꦭꦶ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ꦮꦭꦶ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ꦮꦭꦶ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ꦮꦭꦶ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ꦮꦭꦶ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ꦮꦭꦶ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ꦮꦭꦶ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ꦮꦭꦶ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ꦮꦭꦶ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ꦮꦭꦶ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ꦮꦭꦶ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ꦮꦭꦶ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ꦮꦭꦶ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ꦮꦭꦶ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ꦮꦭꦶ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ꦮꦭꦶ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ꦮꦭꦶ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ꦮꦭꦶ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ꦮꦭꦶ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ꦮꦭꦶ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ꦮꦭꦶ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ꦮꦭꦶ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ꦮꦭꦶ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ꦮꦭꦶ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ꦮꦭꦶ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ꦮꦭꦶ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ꦮꦭꦶ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ꦮꦭꦶ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ꦮꦭꦶ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ꦮꦭꦶ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ꦮꦭꦶ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ꦮꦭꦶ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ꦮꦭꦶ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ꦮꦭꦶ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ꦮꦭꦶ "device not found";
	default:
		ꦮꦭꦶ "unknown error";
	}
}
