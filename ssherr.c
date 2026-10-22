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
ssh_err(ကိန်းပြည့် n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		ပြန်ပေး "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ပြန်ပေး "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ပြန်ပေး "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ပြန်ပေး "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ပြန်ပေး "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ပြန်ပေး "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ပြန်ပေး "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ပြန်ပေး "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ပြန်ပေး "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ပြန်ပေး "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ပြန်ပေး "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ပြန်ပေး "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ပြန်ပေး "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ပြန်ပေး "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ပြန်ပေး "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ပြန်ပေး "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ပြန်ပေး "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ပြန်ပေး "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ပြန်ပေး "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ပြန်ပေး "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ပြန်ပေး "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ပြန်ပေး "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ပြန်ပေး msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ပြန်ပေး "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ပြန်ပေး "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ပြန်ပေး strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ပြန်ပေး "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ပြန်ပေး "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ပြန်ပေး "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ပြန်ပေး "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ပြန်ပေး "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ပြန်ပေး "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ပြန်ပေး "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ပြန်ပေး "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ပြန်ပေး "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ပြန်ပေး "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ပြန်ပေး "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ပြန်ပေး "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ပြန်ပေး "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ပြန်ပေး "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ပြန်ပေး "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ပြန်ပေး "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ပြန်ပေး "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ပြန်ပေး "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ပြန်ပေး "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ပြန်ပေး "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ပြန်ပေး "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ပြန်ပေး "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ပြန်ပေး "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ပြန်ပေး "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ပြန်ပေး "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ပြန်ပေး "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ပြန်ပေး "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ပြန်ပေး "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ပြန်ပေး "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ပြန်ပေး "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ပြန်ပေး "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ပြန်ပေး "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ပြန်ပေး "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ပြန်ပေး "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ပြန်ပေး "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ပြန်ပေး "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ပြန်ပေး "device not found";
	default:
		ပြန်ပေး "unknown error";
	}
}
