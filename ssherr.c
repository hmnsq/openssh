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
		ᰀᰧᰌ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ᰀᰧᰌ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ᰀᰧᰌ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ᰀᰧᰌ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ᰀᰧᰌ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ᰀᰧᰌ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ᰀᰧᰌ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ᰀᰧᰌ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ᰀᰧᰌ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ᰀᰧᰌ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ᰀᰧᰌ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ᰀᰧᰌ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ᰀᰧᰌ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ᰀᰧᰌ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ᰀᰧᰌ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ᰀᰧᰌ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ᰀᰧᰌ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ᰀᰧᰌ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ᰀᰧᰌ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ᰀᰧᰌ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ᰀᰧᰌ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ᰀᰧᰌ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ᰀᰧᰌ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ᰀᰧᰌ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ᰀᰧᰌ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ᰀᰧᰌ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ᰀᰧᰌ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ᰀᰧᰌ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ᰀᰧᰌ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ᰀᰧᰌ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ᰀᰧᰌ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ᰀᰧᰌ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ᰀᰧᰌ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ᰀᰧᰌ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ᰀᰧᰌ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ᰀᰧᰌ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ᰀᰧᰌ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ᰀᰧᰌ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ᰀᰧᰌ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ᰀᰧᰌ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ᰀᰧᰌ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ᰀᰧᰌ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ᰀᰧᰌ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ᰀᰧᰌ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ᰀᰧᰌ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ᰀᰧᰌ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ᰀᰧᰌ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ᰀᰧᰌ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ᰀᰧᰌ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ᰀᰧᰌ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ᰀᰧᰌ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ᰀᰧᰌ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ᰀᰧᰌ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ᰀᰧᰌ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ᰀᰧᰌ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ᰀᰧᰌ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ᰀᰧᰌ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ᰀᰧᰌ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ᰀᰧᰌ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ᰀᰧᰌ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ᰀᰧᰌ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ᰀᰧᰌ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ᰀᰧᰌ "device not found";
	default:
		ᰀᰧᰌ "unknown error";
	}
}
