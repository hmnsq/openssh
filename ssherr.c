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

#ضمن <errno.h>
#ضمن <string.h>
#ضمن "ssherr.h"

ثابت حرف *
ssh_err(صحيح n)
{
	ثابت حرف *msg = عدم;

	بدل (n) {
	حالة SSH_ERR_SUCCESS:
		ܦܢܐ "success";
	حالة SSH_ERR_INTERNAL_ERROR:
		ܦܢܐ "unexpected internal error";
	حالة SSH_ERR_ALLOC_FAIL:
		ܦܢܐ "memory allocation failed";
	حالة SSH_ERR_MESSAGE_INCOMPLETE:
		ܦܢܐ "incomplete message";
	حالة SSH_ERR_INVALID_FORMAT:
		ܦܢܐ "invalid format";
	حالة SSH_ERR_BIGNUM_IS_NEGATIVE:
		ܦܢܐ "bignum is negative";
	حالة SSH_ERR_STRING_TOO_LARGE:
		ܦܢܐ "string is too large";
	حالة SSH_ERR_BIGNUM_TOO_LARGE:
		ܦܢܐ "bignum is too large";
	حالة SSH_ERR_ECPOINT_TOO_LARGE:
		ܦܢܐ "elliptic curve point is too large";
	حالة SSH_ERR_NO_BUFFER_SPACE:
		ܦܢܐ "insufficient buffer space";
	حالة SSH_ERR_INVALID_ARGUMENT:
		ܦܢܐ "invalid argument";
	حالة SSH_ERR_KEY_BITS_MISMATCH:
		ܦܢܐ "key bits do not match";
	حالة SSH_ERR_EC_CURVE_INVALID:
		ܦܢܐ "invalid elliptic curve";
	حالة SSH_ERR_KEY_TYPE_MISMATCH:
		ܦܢܐ "key type does not match";
	حالة SSH_ERR_KEY_TYPE_UNKNOWN:
		ܦܢܐ "unknown or unsupported key type";
	حالة SSH_ERR_EC_CURVE_MISMATCH:
		ܦܢܐ "elliptic curve does not match";
	حالة SSH_ERR_EXPECTED_CERT:
		ܦܢܐ "plain key provided where certificate required";
	حالة SSH_ERR_KEY_LACKS_CERTBLOB:
		ܦܢܐ "key lacks certificate data";
	حالة SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		ܦܢܐ "unknown/unsupported certificate type";
	حالة SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		ܦܢܐ "invalid certificate signing key";
	حالة SSH_ERR_KEY_INVALID_EC_VALUE:
		ܦܢܐ "invalid elliptic curve value";
	حالة SSH_ERR_SIGNATURE_INVALID:
		ܦܢܐ "incorrect signature";
	حالة SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		ܦܢܐ msg != عدم ? msg : "error in libcrypto";
	حالة SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ܦܢܐ "cryptographic operation failed";
	حالة SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ܦܢܐ "unexpected bytes remain after decoding";
	حالة SSH_ERR_SYSTEM_ERROR:
		ܦܢܐ strerror(errno);
	حالة SSH_ERR_KEY_CERT_INVALID:
		ܦܢܐ "invalid certificate";
	حالة SSH_ERR_AGENT_COMMUNICATION:
		ܦܢܐ "communication with agent failed";
	حالة SSH_ERR_AGENT_FAILURE:
		ܦܢܐ "agent refused operation";
	حالة SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ܦܢܐ "DH GEX group out of range";
	حالة SSH_ERR_DISCONNECTED:
		ܦܢܐ "disconnected";
	حالة SSH_ERR_MAC_INVALID:
		ܦܢܐ "message authentication code incorrect";
	حالة SSH_ERR_NO_CIPHER_ALG_MATCH:
		ܦܢܐ "no matching cipher found";
	حالة SSH_ERR_NO_MAC_ALG_MATCH:
		ܦܢܐ "no matching MAC found";
	حالة SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ܦܢܐ "no matching compression method found";
	حالة SSH_ERR_NO_KEX_ALG_MATCH:
		ܦܢܐ "no matching key exchange method found";
	حالة SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ܦܢܐ "no matching host key type found";
	حالة SSH_ERR_PROTOCOL_MISMATCH:
		ܦܢܐ "protocol version mismatch";
	حالة SSH_ERR_NO_PROTOCOL_VERSION:
		ܦܢܐ "could not read protocol version";
	حالة SSH_ERR_NO_HOSTKEY_LOADED:
		ܦܢܐ "could not load host key";
	حالة SSH_ERR_NEED_REKEY:
		ܦܢܐ "rekeying not supported by peer";
	حالة SSH_ERR_PASSPHRASE_TOO_SHORT:
		ܦܢܐ "passphrase is too short (minimum five characters)";
	حالة SSH_ERR_FILE_CHANGED:
		ܦܢܐ "file changed while reading";
	حالة SSH_ERR_KEY_UNKNOWN_CIPHER:
		ܦܢܐ "key encrypted using unsupported cipher";
	حالة SSH_ERR_KEY_WRONG_PASSPHRASE:
		ܦܢܐ "incorrect passphrase supplied to decrypt private key";
	حالة SSH_ERR_KEY_BAD_PERMISSIONS:
		ܦܢܐ "bad permissions";
	حالة SSH_ERR_KEY_CERT_MISMATCH:
		ܦܢܐ "certificate does not match key";
	حالة SSH_ERR_KEY_NOT_FOUND:
		ܦܢܐ "key not found";
	حالة SSH_ERR_AGENT_NOT_PRESENT:
		ܦܢܐ "agent not present";
	حالة SSH_ERR_AGENT_NO_IDENTITIES:
		ܦܢܐ "agent contains no identities";
	حالة SSH_ERR_BUFFER_READ_ONLY:
		ܦܢܐ "internal error: buffer is read-only";
	حالة SSH_ERR_KRL_BAD_MAGIC:
		ܦܢܐ "KRL file has invalid magic number";
	حالة SSH_ERR_KEY_REVOKED:
		ܦܢܐ "Key is revoked";
	حالة SSH_ERR_CONN_CLOSED:
		ܦܢܐ "Connection closed";
	حالة SSH_ERR_CONN_TIMEOUT:
		ܦܢܐ "Connection timed out";
	حالة SSH_ERR_CONN_CORRUPT:
		ܦܢܐ "Connection corrupted";
	حالة SSH_ERR_PROTOCOL_ERROR:
		ܦܢܐ "Protocol error";
	حالة SSH_ERR_KEY_LENGTH:
		ܦܢܐ "Invalid key length";
	حالة SSH_ERR_NUMBER_TOO_LARGE:
		ܦܢܐ "number is too large";
	حالة SSH_ERR_KEY_ALG_UNSUPPORTED:
		ܦܢܐ "key algorithm not supported";
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ܦܢܐ "signature algorithm not supported";
	حالة SSH_ERR_FEATURE_UNSUPPORTED:
		ܦܢܐ "requested feature not supported";
	حالة SSH_ERR_DEVICE_NOT_FOUND:
		ܦܢܐ "device not found";
	افتراضي:
		ܦܢܐ "unknown error";
	}
}
