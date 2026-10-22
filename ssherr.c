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
		ပွၵ်ႈ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ပွၵ်ႈ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ပွၵ်ႈ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ပွၵ်ႈ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ပွၵ်ႈ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ပွၵ်ႈ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ပွၵ်ႈ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ပွၵ်ႈ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ပွၵ်ႈ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ပွၵ်ႈ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ပွၵ်ႈ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ပွၵ်ႈ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ပွၵ်ႈ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ပွၵ်ႈ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ပွၵ်ႈ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ပွၵ်ႈ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ပွၵ်ႈ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ပွၵ်ႈ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ပွၵ်ႈ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ပွၵ်ႈ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ပွၵ်ႈ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ပွၵ်ႈ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ပွၵ်ႈ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ပွၵ်ႈ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ပွၵ်ႈ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ပွၵ်ႈ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ပွၵ်ႈ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ပွၵ်ႈ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ပွၵ်ႈ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ပွၵ်ႈ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ပွၵ်ႈ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ပွၵ်ႈ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ပွၵ်ႈ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ပွၵ်ႈ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ပွၵ်ႈ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ပွၵ်ႈ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ပွၵ်ႈ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ပွၵ်ႈ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ပွၵ်ႈ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ပွၵ်ႈ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ပွၵ်ႈ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ပွၵ်ႈ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ပွၵ်ႈ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ပွၵ်ႈ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ပွၵ်ႈ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ပွၵ်ႈ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ပွၵ်ႈ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ပွၵ်ႈ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ပွၵ်ႈ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ပွၵ်ႈ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ပွၵ်ႈ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ပွၵ်ႈ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ပွၵ်ႈ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ပွၵ်ႈ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ပွၵ်ႈ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ပွၵ်ႈ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ပွၵ်ႈ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ပွၵ်ႈ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ပွၵ်ႈ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ပွၵ်ႈ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ပွၵ်ႈ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ပွၵ်ႈ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ပွၵ်ႈ "device not found";
	default:
		ပွၵ်ႈ "unknown error";
	}
}
