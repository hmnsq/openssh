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
		ᯀᯮᯞ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ᯀᯮᯞ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ᯀᯮᯞ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ᯀᯮᯞ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ᯀᯮᯞ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ᯀᯮᯞ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ᯀᯮᯞ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ᯀᯮᯞ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ᯀᯮᯞ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ᯀᯮᯞ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ᯀᯮᯞ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ᯀᯮᯞ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ᯀᯮᯞ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ᯀᯮᯞ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ᯀᯮᯞ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ᯀᯮᯞ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ᯀᯮᯞ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ᯀᯮᯞ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ᯀᯮᯞ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ᯀᯮᯞ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ᯀᯮᯞ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ᯀᯮᯞ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ᯀᯮᯞ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ᯀᯮᯞ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ᯀᯮᯞ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ᯀᯮᯞ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ᯀᯮᯞ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ᯀᯮᯞ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ᯀᯮᯞ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ᯀᯮᯞ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ᯀᯮᯞ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ᯀᯮᯞ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ᯀᯮᯞ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ᯀᯮᯞ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ᯀᯮᯞ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ᯀᯮᯞ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ᯀᯮᯞ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ᯀᯮᯞ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ᯀᯮᯞ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ᯀᯮᯞ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ᯀᯮᯞ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ᯀᯮᯞ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ᯀᯮᯞ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ᯀᯮᯞ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ᯀᯮᯞ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ᯀᯮᯞ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ᯀᯮᯞ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ᯀᯮᯞ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ᯀᯮᯞ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ᯀᯮᯞ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ᯀᯮᯞ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ᯀᯮᯞ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ᯀᯮᯞ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ᯀᯮᯞ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ᯀᯮᯞ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ᯀᯮᯞ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ᯀᯮᯞ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ᯀᯮᯞ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ᯀᯮᯞ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ᯀᯮᯞ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ᯀᯮᯞ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ᯀᯮᯞ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ᯀᯮᯞ "device not found";
	default:
		ᯀᯮᯞ "unknown error";
	}
}
