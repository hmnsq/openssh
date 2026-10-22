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
		ᬯᬮᬶ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ᬯᬮᬶ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ᬯᬮᬶ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ᬯᬮᬶ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ᬯᬮᬶ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ᬯᬮᬶ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ᬯᬮᬶ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ᬯᬮᬶ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ᬯᬮᬶ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ᬯᬮᬶ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ᬯᬮᬶ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ᬯᬮᬶ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ᬯᬮᬶ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ᬯᬮᬶ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ᬯᬮᬶ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ᬯᬮᬶ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ᬯᬮᬶ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ᬯᬮᬶ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ᬯᬮᬶ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ᬯᬮᬶ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ᬯᬮᬶ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ᬯᬮᬶ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ᬯᬮᬶ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ᬯᬮᬶ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ᬯᬮᬶ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ᬯᬮᬶ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ᬯᬮᬶ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ᬯᬮᬶ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ᬯᬮᬶ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ᬯᬮᬶ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ᬯᬮᬶ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ᬯᬮᬶ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ᬯᬮᬶ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ᬯᬮᬶ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ᬯᬮᬶ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ᬯᬮᬶ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ᬯᬮᬶ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ᬯᬮᬶ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ᬯᬮᬶ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ᬯᬮᬶ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ᬯᬮᬶ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ᬯᬮᬶ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ᬯᬮᬶ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ᬯᬮᬶ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ᬯᬮᬶ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ᬯᬮᬶ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ᬯᬮᬶ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ᬯᬮᬶ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ᬯᬮᬶ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ᬯᬮᬶ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ᬯᬮᬶ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ᬯᬮᬶ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ᬯᬮᬶ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ᬯᬮᬶ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ᬯᬮᬶ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ᬯᬮᬶ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ᬯᬮᬶ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ᬯᬮᬶ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ᬯᬮᬶ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ᬯᬮᬶ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ᬯᬮᬶ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ᬯᬮᬶ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ᬯᬮᬶ "device not found";
	default:
		ᬯᬮᬶ "unknown error";
	}
}
