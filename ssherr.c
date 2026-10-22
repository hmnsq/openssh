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

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ "ssherr.h"

અચલ અક્ષર *
ssh_err(પૂર્ણાંક n)
{
	અચલ અક્ષર *સંદેશ = ખાલી;

	પસંદગી (n) {
	સ્થિતિ SSH_ERR_SUCCESS:
		પાછા "success";
	સ્થિતિ SSH_ERR_INTERNAL_ERROR:
		પાછા "unexpected internal error";
	સ્થિતિ SSH_ERR_ALLOC_FAIL:
		પાછા "memory allocation failed";
	સ્થિતિ SSH_ERR_MESSAGE_INCOMPLETE:
		પાછા "incomplete message";
	સ્થિતિ SSH_ERR_INVALID_FORMAT:
		પાછા "invalid format";
	સ્થિતિ SSH_ERR_BIGNUM_IS_NEGATIVE:
		પાછા "bignum is negative";
	સ્થિતિ SSH_ERR_STRING_TOO_LARGE:
		પાછા "string is too large";
	સ્થિતિ SSH_ERR_BIGNUM_TOO_LARGE:
		પાછા "bignum is too large";
	સ્થિતિ SSH_ERR_ECPOINT_TOO_LARGE:
		પાછા "elliptic curve point is too large";
	સ્થિતિ SSH_ERR_NO_BUFFER_SPACE:
		પાછા "insufficient buffer space";
	સ્થિતિ SSH_ERR_INVALID_ARGUMENT:
		પાછા "invalid argument";
	સ્થિતિ SSH_ERR_ચાવી_BITS_MISMATCH:
		પાછા "key bits do not match";
	સ્થિતિ SSH_ERR_EC_CURVE_INVALID:
		પાછા "invalid elliptic curve";
	સ્થિતિ SSH_ERR_ચાવી_TYPE_MISMATCH:
		પાછા "key type does not match";
	સ્થિતિ SSH_ERR_ચાવી_TYPE_UNKNOWN:
		પાછા "unknown or unsupported key type";
	સ્થિતિ SSH_ERR_EC_CURVE_MISMATCH:
		પાછા "elliptic curve does not match";
	સ્થિતિ SSH_ERR_EXPECTED_CERT:
		પાછા "plain key provided where certificate required";
	સ્થિતિ SSH_ERR_ચાવી_LACKS_CERTBLOB:
		પાછા "key lacks certificate data";
	સ્થિતિ SSH_ERR_ચાવી_CERT_UNKNOWN_TYPE:
		પાછા "unknown/unsupported certificate type";
	સ્થિતિ SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી:
		પાછા "invalid certificate signing key";
	સ્થિતિ SSH_ERR_ચાવી_INVALID_EC_કિંમત:
		પાછા "invalid elliptic curve value";
	સ્થિતિ SSH_ERR_SIGNATURE_INVALID:
		પાછા "incorrect signature";
	સ્થિતિ SSH_ERR_LIBCRYPTO_ERROR:
		સંદેશ = ssherr_libcrypto();
		પાછા સંદેશ != ખાલી ? સંદેશ : "error in libcrypto";
	સ્થિતિ SSH_ERR_INTERNAL_CRYPTO_ERROR:
		પાછા "cryptographic operation failed";
	સ્થિતિ SSH_ERR_UNEXPECTED_TRAILING_DATA:
		પાછા "unexpected bytes remain after decoding";
	સ્થિતિ SSH_ERR_SYSTEM_ERROR:
		પાછા strerror(errno);
	સ્થિતિ SSH_ERR_ચાવી_CERT_INVALID:
		પાછા "invalid certificate";
	સ્થિતિ SSH_ERR_AGENT_COMMUNICATION:
		પાછા "communication with agent failed";
	સ્થિતિ SSH_ERR_AGENT_FAILURE:
		પાછા "agent refused operation";
	સ્થિતિ SSH_ERR_DH_GEX_OUT_OF_RANGE:
		પાછા "DH GEX group out of range";
	સ્થિતિ SSH_ERR_DISCONNECTED:
		પાછા "disconnected";
	સ્થિતિ SSH_ERR_MAC_INVALID:
		પાછા "message authentication code incorrect";
	સ્થિતિ SSH_ERR_NO_CIPHER_ALG_MATCH:
		પાછા "no matching cipher found";
	સ્થિતિ SSH_ERR_NO_MAC_ALG_MATCH:
		પાછા "no matching MAC found";
	સ્થિતિ SSH_ERR_NO_COMPRESS_ALG_MATCH:
		પાછા "no matching compression method found";
	સ્થિતિ SSH_ERR_NO_KEX_ALG_MATCH:
		પાછા "no matching key exchange method found";
	સ્થિતિ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		પાછા "no matching host key type found";
	સ્થિતિ SSH_ERR_PROTOCOL_MISMATCH:
		પાછા "protocol version mismatch";
	સ્થિતિ SSH_ERR_NO_PROTOCOL_VERSION:
		પાછા "could not read protocol version";
	સ્થિતિ SSH_ERR_NO_HOSTKEY_LOADED:
		પાછા "could not load host key";
	સ્થિતિ SSH_ERR_NEED_REKEY:
		પાછા "rekeying not supported by peer";
	સ્થિતિ SSH_ERR_PASSPHRASE_TOO_SHORT:
		પાછા "passphrase is too short (minimum five characters)";
	સ્થિતિ SSH_ERR_FILE_CHANGED:
		પાછા "file changed while reading";
	સ્થિતિ SSH_ERR_ચાવી_UNKNOWN_CIPHER:
		પાછા "key encrypted using unsupported cipher";
	સ્થિતિ SSH_ERR_ચાવી_WRONG_PASSPHRASE:
		પાછા "incorrect passphrase supplied to decrypt private key";
	સ્થિતિ SSH_ERR_ચાવી_BAD_PERMISSIONS:
		પાછા "bad permissions";
	સ્થિતિ SSH_ERR_ચાવી_CERT_MISMATCH:
		પાછા "certificate does not match key";
	સ્થિતિ SSH_ERR_ચાવી_NOT_FOUND:
		પાછા "key not found";
	સ્થિતિ SSH_ERR_AGENT_NOT_PRESENT:
		પાછા "agent not present";
	સ્થિતિ SSH_ERR_AGENT_NO_IDENTITIES:
		પાછા "agent contains no identities";
	સ્થિતિ SSH_ERR_BUFFER_READ_ONLY:
		પાછા "internal error: buffer is read-only";
	સ્થિતિ SSH_ERR_KRL_BAD_MAGIC:
		પાછા "KRL file has invalid magic number";
	સ્થિતિ SSH_ERR_ચાવી_REVOKED:
		પાછા "Key is revoked";
	સ્થિતિ SSH_ERR_CONN_CLOSED:
		પાછા "Connection closed";
	સ્થિતિ SSH_ERR_CONN_TIMEOUT:
		પાછા "Connection timed out";
	સ્થિતિ SSH_ERR_CONN_CORRUPT:
		પાછા "Connection corrupted";
	સ્થિતિ SSH_ERR_PROTOCOL_ERROR:
		પાછા "Protocol error";
	સ્થિતિ SSH_ERR_ચાવી_LENGTH:
		પાછા "Invalid key length";
	સ્થિતિ SSH_ERR_સંખ્યા_TOO_LARGE:
		પાછા "number is too large";
	સ્થિતિ SSH_ERR_ચાવી_ALG_UNSUPPORTED:
		પાછા "key algorithm not supported";
	સ્થિતિ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		પાછા "signature algorithm not supported";
	સ્થિતિ SSH_ERR_FEATURE_UNSUPPORTED:
		પાછા "requested feature not supported";
	સ્થિતિ SSH_ERR_DEVICE_NOT_FOUND:
		પાછા "device not found";
	મૂળભૂત:
		પાછા "unknown error";
	}
}
