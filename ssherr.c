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
	ثابت حرف *ئۇچۇر = عدم;

	بدل (n) {
	حالة SSH_ERR_SUCCESS:
		أرجع "success";
	حالة SSH_ERR_INTERNAL_ERROR:
		أرجع "unexpected internal error";
	حالة SSH_ERR_ALLOC_FAIL:
		أرجع "memory allocation failed";
	حالة SSH_ERR_MESSAGE_INCOMPLETE:
		أرجع "incomplete message";
	حالة SSH_ERR_INVALID_FORMAT:
		أرجع "invalid format";
	حالة SSH_ERR_BIGNUM_IS_NEGATIVE:
		أرجع "bignum is negative";
	حالة SSH_ERR_STRING_TOO_LARGE:
		أرجع "string is too large";
	حالة SSH_ERR_BIGNUM_TOO_LARGE:
		أرجع "bignum is too large";
	حالة SSH_ERR_ECPOINT_TOO_LARGE:
		أرجع "elliptic curve point is too large";
	حالة SSH_ERR_NO_BUFFER_SPACE:
		أرجع "insufficient buffer space";
	حالة SSH_ERR_INVALID_ARGUMENT:
		أرجع "invalid argument";
	حالة SSH_ERR_ئاچقۇچ_BITS_MISMATCH:
		أرجع "key bits do not match";
	حالة SSH_ERR_EC_CURVE_INVALID:
		أرجع "invalid elliptic curve";
	حالة SSH_ERR_ئاچقۇچ_TYPE_MISMATCH:
		أرجع "key type does not match";
	حالة SSH_ERR_ئاچقۇچ_TYPE_UNKNOWN:
		أرجع "unknown or unsupported key type";
	حالة SSH_ERR_EC_CURVE_MISMATCH:
		أرجع "elliptic curve does not match";
	حالة SSH_ERR_EXPECTED_CERT:
		أرجع "plain key provided where certificate required";
	حالة SSH_ERR_ئاچقۇچ_LACKS_CERTBLOB:
		أرجع "key lacks certificate data";
	حالة SSH_ERR_ئاچقۇچ_CERT_UNKNOWN_TYPE:
		أرجع "unknown/unsupported certificate type";
	حالة SSH_ERR_ئاچقۇچ_CERT_INVALID_SIGN_ئاچقۇچ:
		أرجع "invalid certificate signing key";
	حالة SSH_ERR_ئاچقۇچ_INVALID_EC_قىممەت:
		أرجع "invalid elliptic curve value";
	حالة SSH_ERR_SIGNATURE_INVALID:
		أرجع "incorrect signature";
	حالة SSH_ERR_LIBCRYPTO_ERROR:
		ئۇچۇر = ssherr_libcrypto();
		أرجع ئۇچۇر != عدم ? ئۇچۇر : "error in libcrypto";
	حالة SSH_ERR_INTERNAL_CRYPTO_ERROR:
		أرجع "cryptographic operation failed";
	حالة SSH_ERR_UNEXPECTED_TRAILING_DATA:
		أرجع "unexpected bytes remain after decoding";
	حالة SSH_ERR_SYSTEM_ERROR:
		أرجع strerror(errno);
	حالة SSH_ERR_ئاچقۇچ_CERT_INVALID:
		أرجع "invalid certificate";
	حالة SSH_ERR_AGENT_COMMUNICATION:
		أرجع "communication with agent failed";
	حالة SSH_ERR_AGENT_FAILURE:
		أرجع "agent refused operation";
	حالة SSH_ERR_DH_GEX_OUT_OF_RANGE:
		أرجع "DH GEX group out of range";
	حالة SSH_ERR_DISCONNECTED:
		أرجع "disconnected";
	حالة SSH_ERR_MAC_INVALID:
		أرجع "message authentication code incorrect";
	حالة SSH_ERR_NO_CIPHER_ALG_MATCH:
		أرجع "no matching cipher found";
	حالة SSH_ERR_NO_MAC_ALG_MATCH:
		أرجع "no matching MAC found";
	حالة SSH_ERR_NO_COMPRESS_ALG_MATCH:
		أرجع "no matching compression method found";
	حالة SSH_ERR_NO_KEX_ALG_MATCH:
		أرجع "no matching key exchange method found";
	حالة SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		أرجع "no matching host key type found";
	حالة SSH_ERR_PROTOCOL_MISMATCH:
		أرجع "protocol version mismatch";
	حالة SSH_ERR_NO_PROTOCOL_VERSION:
		أرجع "could not read protocol version";
	حالة SSH_ERR_NO_HOSTKEY_LOADED:
		أرجع "could not load host key";
	حالة SSH_ERR_NEED_REKEY:
		أرجع "rekeying not supported by peer";
	حالة SSH_ERR_PASSPHRASE_TOO_SHORT:
		أرجع "passphrase is too short (minimum five characters)";
	حالة SSH_ERR_FILE_CHANGED:
		أرجع "file changed while reading";
	حالة SSH_ERR_ئاچقۇچ_UNKNOWN_CIPHER:
		أرجع "key encrypted using unsupported cipher";
	حالة SSH_ERR_ئاچقۇچ_WRONG_PASSPHRASE:
		أرجع "incorrect passphrase supplied to decrypt private key";
	حالة SSH_ERR_ئاچقۇچ_BAD_PERMISSIONS:
		أرجع "bad permissions";
	حالة SSH_ERR_ئاچقۇچ_CERT_MISMATCH:
		أرجع "certificate does not match key";
	حالة SSH_ERR_ئاچقۇچ_NOT_FOUND:
		أرجع "key not found";
	حالة SSH_ERR_AGENT_NOT_PRESENT:
		أرجع "agent not present";
	حالة SSH_ERR_AGENT_NO_IDENTITIES:
		أرجع "agent contains no identities";
	حالة SSH_ERR_BUFFER_READ_ONLY:
		أرجع "internal error: buffer is read-only";
	حالة SSH_ERR_KRL_BAD_MAGIC:
		أرجع "KRL file has invalid magic number";
	حالة SSH_ERR_ئاچقۇچ_REVOKED:
		أرجع "Key is revoked";
	حالة SSH_ERR_CONN_CLOSED:
		أرجع "Connection closed";
	حالة SSH_ERR_CONN_TIMEOUT:
		أرجع "Connection timed out";
	حالة SSH_ERR_CONN_CORRUPT:
		أرجع "Connection corrupted";
	حالة SSH_ERR_PROTOCOL_ERROR:
		أرجع "Protocol error";
	حالة SSH_ERR_ئاچقۇچ_LENGTH:
		أرجع "Invalid key length";
	حالة SSH_ERR_سان_TOO_LARGE:
		أرجع "number is too large";
	حالة SSH_ERR_ئاچقۇچ_ALG_UNSUPPORTED:
		أرجع "key algorithm not supported";
	حالة SSH_ERR_SIGN_ALG_UNSUPPORTED:
		أرجع "signature algorithm not supported";
	حالة SSH_ERR_FEATURE_UNSUPPORTED:
		أرجع "requested feature not supported";
	حالة SSH_ERR_DEVICE_NOT_FOUND:
		أرجع "device not found";
	افتراضي:
		أرجع "unknown error";
	}
}
