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
ssh_err(පූර්ණ_සංඛ්‍යා n)
{
	const var_na *msg = NULL;

	switch (n) {
	pak_sa SSH_ERR_SUCCESS:
		ආපසු "success";
	pak_sa SSH_ERR_INTERNAL_ERROR:
		ආපසු "unexpected internal error";
	pak_sa SSH_ERR_ALLOC_FAIL:
		ආපසු "memory allocation failed";
	pak_sa SSH_ERR_MESSAGE_INCOMPLETE:
		ආපසු "incomplete message";
	pak_sa SSH_ERR_INVALID_FORMAT:
		ආපසු "invalid format";
	pak_sa SSH_ERR_BIGNUM_IS_NEGATIVE:
		ආපසු "bignum is negative";
	pak_sa SSH_ERR_STRING_TOO_LARGE:
		ආපසු "string is too large";
	pak_sa SSH_ERR_BIGNUM_TOO_LARGE:
		ආපසු "bignum is too large";
	pak_sa SSH_ERR_ECPOINT_TOO_LARGE:
		ආපසු "elliptic curve point is too large";
	pak_sa SSH_ERR_NO_BUFFER_SPACE:
		ආපසු "insufficient buffer space";
	pak_sa SSH_ERR_INVALID_ARGUMENT:
		ආපසු "invalid argument";
	pak_sa SSH_ERR_KEY_BITS_MISMATCH:
		ආපසු "key bits do not match";
	pak_sa SSH_ERR_EC_CURVE_INVALID:
		ආපසු "invalid elliptic curve";
	pak_sa SSH_ERR_KEY_TYPE_MISMATCH:
		ආපසු "key type does not match";
	pak_sa SSH_ERR_KEY_TYPE_UNKNOWN:
		ආපසු "unknown or unsupported key type";
	pak_sa SSH_ERR_EC_CURVE_MISMATCH:
		ආපසු "elliptic curve does not match";
	pak_sa SSH_ERR_EXPECTED_CERT:
		ආපසු "plain key provided where certificate required";
	pak_sa SSH_ERR_KEY_LACKS_CERTBLOB:
		ආපසු "key lacks certificate data";
	pak_sa SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ආපසු "unknown/unsupported certificate type";
	pak_sa SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ආපසු "invalid certificate signing key";
	pak_sa SSH_ERR_KEY_INVALID_EC_VALUE:
		ආපසු "invalid elliptic curve value";
	pak_sa SSH_ERR_SIGNATURE_INVALID:
		ආපසු "incorrect signature";
	pak_sa SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ආපසු msg != NULL ? msg : "error in libcrypto";
	pak_sa SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ආපසු "cryptographic operation failed";
	pak_sa SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ආපසු "unexpected bytes remain after decoding";
	pak_sa SSH_ERR_SYSTEM_ERROR:
		ආපසු strerror(errno);
	pak_sa SSH_ERR_KEY_CERT_INVALID:
		ආපසු "invalid certificate";
	pak_sa SSH_ERR_AGENT_COMMUNICATION:
		ආපසු "communication with agent failed";
	pak_sa SSH_ERR_AGENT_FAILURE:
		ආපසු "agent refused operation";
	pak_sa SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ආපසු "DH GEX group out of range";
	pak_sa SSH_ERR_DISCONNECTED:
		ආපසු "disconnected";
	pak_sa SSH_ERR_MAC_INVALID:
		ආපසු "message authentication code incorrect";
	pak_sa SSH_ERR_NO_CIPHER_ALG_MATCH:
		ආපසු "no matching cipher found";
	pak_sa SSH_ERR_NO_MAC_ALG_MATCH:
		ආපසු "no matching MAC found";
	pak_sa SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ආපසු "no matching compression method found";
	pak_sa SSH_ERR_NO_KEX_ALG_MATCH:
		ආපසු "no matching key exchange method found";
	pak_sa SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ආපසු "no matching host key type found";
	pak_sa SSH_ERR_PROTOCOL_MISMATCH:
		ආපසු "protocol version mismatch";
	pak_sa SSH_ERR_NO_PROTOCOL_VERSION:
		ආපසු "could not read protocol version";
	pak_sa SSH_ERR_NO_HOSTKEY_LOADED:
		ආපසු "could not load host key";
	pak_sa SSH_ERR_NEED_REKEY:
		ආපසු "rekeying not supported by peer";
	pak_sa SSH_ERR_PASSPHRASE_TOO_SHORT:
		ආපසු "passphrase is too short (minimum five characters)";
	pak_sa SSH_ERR_FILE_CHANGED:
		ආපසු "file changed while reading";
	pak_sa SSH_ERR_KEY_UNKNOWN_CIPHER:
		ආපසු "key encrypted using unsupported cipher";
	pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
		ආපසු "incorrect passphrase supplied to decrypt private key";
	pak_sa SSH_ERR_KEY_BAD_PERMISSIONS:
		ආපසු "bad permissions";
	pak_sa SSH_ERR_KEY_CERT_MISMATCH:
		ආපසු "certificate does not match key";
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		ආපසු "key not found";
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		ආපසු "agent not present";
	pak_sa SSH_ERR_AGENT_NO_IDENTITIES:
		ආපසු "agent contains no identities";
	pak_sa SSH_ERR_BUFFER_READ_ONLY:
		ආපසු "internal error: buffer is read-only";
	pak_sa SSH_ERR_KRL_BAD_MAGIC:
		ආපසු "KRL file has invalid magic number";
	pak_sa SSH_ERR_KEY_REVOKED:
		ආපසු "Key is revoked";
	pak_sa SSH_ERR_CONN_CLOSED:
		ආපසු "Connection closed";
	pak_sa SSH_ERR_CONN_TIMEOUT:
		ආපසු "Connection timed out";
	pak_sa SSH_ERR_CONN_CORRUPT:
		ආපසු "Connection corrupted";
	pak_sa SSH_ERR_PROTOCOL_ERROR:
		ආපසු "Protocol error";
	pak_sa SSH_ERR_KEY_LENGTH:
		ආපසු "Invalid key length";
	pak_sa SSH_ERR_NUMBER_TOO_LARGE:
		ආපසු "number is too large";
	pak_sa SSH_ERR_KEY_ALG_UNSUPPORTED:
		ආපසු "key algorithm not supported";
	pak_sa SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ආපසු "signature algorithm not supported";
	pak_sa SSH_ERR_FEATURE_UNSUPPORTED:
		ආපසු "requested feature not supported";
	pak_sa SSH_ERR_DEVICE_NOT_FOUND:
		ආපසු "device not found";
	default:
		ආපසු "unknown error";
	}
}
