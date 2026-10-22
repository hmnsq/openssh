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
ssh_err(ຈຳນວນເຕັມ n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		ສົ່ງຄືນ "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ສົ່ງຄືນ "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ສົ່ງຄືນ "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ສົ່ງຄືນ "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ສົ່ງຄືນ "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ສົ່ງຄືນ "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ສົ່ງຄືນ "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ສົ່ງຄືນ "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ສົ່ງຄືນ "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ສົ່ງຄືນ "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ສົ່ງຄືນ "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ສົ່ງຄືນ "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ສົ່ງຄືນ "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ສົ່ງຄືນ "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ສົ່ງຄືນ "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ສົ່ງຄືນ "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ສົ່ງຄືນ "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ສົ່ງຄືນ "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ສົ່ງຄືນ "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ສົ່ງຄືນ "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ສົ່ງຄືນ "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ສົ່ງຄືນ "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ສົ່ງຄືນ msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ສົ່ງຄືນ "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ສົ່ງຄືນ "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ສົ່ງຄືນ strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ສົ່ງຄືນ "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ສົ່ງຄືນ "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ສົ່ງຄືນ "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ສົ່ງຄືນ "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ສົ່ງຄືນ "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ສົ່ງຄືນ "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ສົ່ງຄືນ "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ສົ່ງຄືນ "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ສົ່ງຄືນ "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ສົ່ງຄືນ "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ສົ່ງຄືນ "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ສົ່ງຄືນ "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ສົ່ງຄືນ "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ສົ່ງຄືນ "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ສົ່ງຄືນ "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ສົ່ງຄືນ "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ສົ່ງຄືນ "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ສົ່ງຄືນ "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ສົ່ງຄືນ "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ສົ່ງຄືນ "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ສົ່ງຄືນ "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ສົ່ງຄືນ "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ສົ່ງຄືນ "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ສົ່ງຄືນ "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ສົ່ງຄືນ "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ສົ່ງຄືນ "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ສົ່ງຄືນ "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ສົ່ງຄືນ "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ສົ່ງຄືນ "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ສົ່ງຄືນ "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ສົ່ງຄືນ "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ສົ່ງຄືນ "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ສົ່ງຄືນ "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ສົ່ງຄືນ "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ສົ່ງຄືນ "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ສົ່ງຄືນ "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ສົ່ງຄືນ "device not found";
	default:
		ສົ່ງຄືນ "unknown error";
	}
}
