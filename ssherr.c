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
		החזר "success";
	حالة SSH_ERR_INTERNAL_ERROR:
		החזר "unexpected internal error";
	حالة SSH_ERR_ALLOC_FAIL:
		החזר "memory allocation failed";
	حالة SSH_ERR_MESSAGE_INCOMPLETE:
		החזר "incomplete message";
	حالة SSH_ERR_INVALID_FORMAT:
		החזר "invalid format";
	حالة SSH_ERR_BIGNUM_IS_NEGATIVE:
		החזר "bignum is negative";
	حالة SSH_ERR_STRING_TOO_LARGE:
		החזר "string is too large";
	حالة SSH_ERR_BIGNUM_TOO_LARGE:
		החזר "bignum is too large";
	حالة SSH_ERR_ECPOINT_TOO_LARGE:
		החזר "elliptic curve point is too large";
	حالة SSH_ERR_NO_BUFFER_SPACE:
		החזר "insufficient buffer space";
	حالة SSH_ERR_INVALID_ARGUMENT:
		החזר "invalid argument";
	حالة SSH_ERR_KEY_BITS_MISMATCH:
		החזר "key bits do not match";
	حالة SSH_ERR_EC_CURVE_INVALID:
		החזר "invalid elliptic curve";
	حالة SSH_ERR_KEY_TYPE_MISMATCH:
		החזר "key type does not match";
	حالة SSH_ERR_KEY_TYPE_UNKNOWN:
		החזר "unknown or unsupported key type";
	حالة SSH_ERR_EC_CURVE_MISMATCH:
		החזר "elliptic curve does not match";
	حالة SSH_ERR_EXPECTED_CERT:
		החזר "plain key provided where certificate required";
	حالة SSH_ERR_KEY_LACKS_CERTBLOB:
		החזר "key lacks certificate data";
	حالة SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		החזר "unknown/unsupported certificate type";
	حالة SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		החזר "invalid certificate signing key";
	حالة SSH_ERR_KEY_INVALID_EC_VALUE:
		החזר "invalid elliptic curve value";
	حالة SSH_ERR_SIGNATURE_INVALID:
		החזר "incorrect signature";
	حالة SSH_ERR_LIBCRYPTO_ERROR:
		msg = ssherr_libcrypto();
		החזר msg != عدم ? msg : "error in libcrypto";
	حالة SSH_ERR_INTERNAL_CRYPTO_ERROR:
		החזר "cryptographic operation failed";
	حالة SSH_ERR_UNEXPECTED_TRAILING_DATA:
		החזר "unexpected bytes remain after decoding";
	حالة SSH_ERR_SYSTEM_ERROR:
		החזר strerror(errno);
	حالة SSH_ERR_KEY_CERT_INVALID:
		החזר "invalid certificate";
	حالة SSH_ERR_AGENT_COMMUNICATION:
		החזר "communication with agent failed";
	حالة SSH_ERR_AGENT_FAILURE:
		החזר "agent refused operation";
	حالة SSH_ERR_DH_GEX_OUT_OF_RANGE:
		החזר "DH GEX group out of range";
	حالة SSH_ERR_DISCONNECTED:
		החזר "disconnected";
	حالة SSH_ERR_MAC_INVALID:
		החזר "message authentication code incorrect";
	حالة SSH_ERR_NO_CIPHER_ALG_MATCH:
		החזר "no matching cipher found";
	حالة SSH_ERR_NO_MAC_ALG_MATCH:
		החזר "no matching MAC found";
	حالة SSH_ERR_NO_COMPRESS_ALG_MATCH:
		החזר "no matching compression method found";
	حالة SSH_ERR_NO_KEX_ALG_MATCH:
		החזר "no matching key exchange method found";
	حالة SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		החזר "no matching host key type found";
	حالة SSH_ERR_PROTOCOL_MISMATCH:
		החזר "protocol version mismatch";
	حالة SSH_ERR_NO_PROTOCOL_VERSION:
		החזר "could not read protocol version";
	حالة SSH_ERR_NO_HOSTKEY_LOADED:
		החזר "could not load host key";
	حالة SSH_ERR_NEED_REKEY:
		החזר "rekeying not supported by peer";
	حالة SSH_ERR_PASSPHRASE_TOO_SHORT:
		החזר "passphrase is too short (minimum five characters)";
	حالة SSH_ERR_FILE_CHANGED:
		החזר "file changed while reading";
	حالة SSH_ERR_KEY_UNKNOWN_CIPHER:
		החזר "key encrypted using unsupported cipher";
	حالة SSH_ERR_KEY_WRONG_PASSPHRASE:
		החזר "incorrect passphrase supplied to decrypt private key";
	حالة SSH_ERR_KEY_BAD_PERMISSIONS:
		החזר "bad permissions";
	حالة SSH_ERR_KEY_CERT_MISMATCH:
		החזר "certificate does not match key";
	حالة SSH_ERR_KEY_NOT_FOUND:
		החזר "key not found";
	حالة SSH_ERR_AGENT_NOT_PRESENT:
		החזר "agent not present";
	حالة SSH_ERR_AGENT_NO_IDENTITIES:
		החזר "agent contains no identities";
	حالة SSH_ERR_BUFFER_READ_ONLY:
		החזר "internal error: buffer is read-only";
	حالة SSH_ERR_KRL_BAD_MAGIC:
		החזר "KRL file has invalid magic number";
	حالة SSH_ERR_KEY_REVOKED:
		החזר "Key is revoked";
	حالة SSH_ERR_CONN_CLOSED:
		החזר "Connection closed";
	حالة SSH_ERR_CONN_TIMEOUT:
		החזר "Connection timed out";
	حالة SSH_ERR_CONN_CORRUPT:
		החזר "Connection corrupted";
	حالة SSH_ERR_PROTOCOL_ERROR:
		החזר "Protocol error";
	حالة SSH_ERR_KEY_LENGTH:
		החזר "Invalid key length";
	حالة SSH_ERR_NUMBER_TOO_LARGE:
		החזר "number is too large";
	حالة SSH_ERR_KEY_ALG_UNSUPPORTED:
		החזר "key algorithm not supported";
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		החזר "signature algorithm not supported";
	حالة SSH_ERR_FEATURE_UNSUPPORTED:
		החזר "requested feature not supported";
	حالة SSH_ERR_DEVICE_NOT_FOUND:
		החזר "device not found";
	افتراضي:
		החזר "unknown error";
	}
}
