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
		ᤀᤡᤴ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ᤀᤡᤴ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ᤀᤡᤴ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ᤀᤡᤴ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ᤀᤡᤴ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ᤀᤡᤴ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ᤀᤡᤴ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ᤀᤡᤴ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ᤀᤡᤴ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ᤀᤡᤴ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ᤀᤡᤴ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ᤀᤡᤴ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ᤀᤡᤴ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ᤀᤡᤴ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ᤀᤡᤴ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ᤀᤡᤴ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ᤀᤡᤴ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ᤀᤡᤴ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ᤀᤡᤴ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ᤀᤡᤴ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ᤀᤡᤴ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ᤀᤡᤴ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ᤀᤡᤴ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ᤀᤡᤴ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ᤀᤡᤴ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ᤀᤡᤴ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ᤀᤡᤴ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ᤀᤡᤴ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ᤀᤡᤴ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ᤀᤡᤴ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ᤀᤡᤴ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ᤀᤡᤴ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ᤀᤡᤴ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ᤀᤡᤴ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ᤀᤡᤴ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ᤀᤡᤴ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ᤀᤡᤴ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ᤀᤡᤴ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ᤀᤡᤴ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ᤀᤡᤴ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ᤀᤡᤴ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ᤀᤡᤴ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ᤀᤡᤴ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ᤀᤡᤴ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ᤀᤡᤴ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ᤀᤡᤴ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ᤀᤡᤴ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ᤀᤡᤴ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ᤀᤡᤴ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ᤀᤡᤴ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ᤀᤡᤴ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ᤀᤡᤴ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ᤀᤡᤴ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ᤀᤡᤴ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ᤀᤡᤴ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ᤀᤡᤴ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ᤀᤡᤴ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ᤀᤡᤴ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ᤀᤡᤴ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ᤀᤡᤴ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ᤀᤡᤴ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ᤀᤡᤴ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ᤀᤡᤴ "device not found";
	default:
		ᤀᤡᤴ "unknown error";
	}
}
