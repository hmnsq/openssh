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

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਅਚਲ ਅੱਖਰ *
ssh_err(ਪੂਰਨ n)
{
	ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;

	ਚੋਣ (n) {
	ਹਾਲਤ SSH_ERR_SUCCESS:
		ਵਾਪਸ "success";
	ਹਾਲਤ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR:
		ਵਾਪਸ "unexpected internal error";
	ਹਾਲਤ SSH_ERR_ALLOC_FAIL:
		ਵਾਪਸ "memory allocation failed";
	ਹਾਲਤ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE:
		ਵਾਪਸ "incomplete message";
	ਹਾਲਤ SSH_ERR_INVALID_FORMAT:
		ਵਾਪਸ "invalid format";
	ਹਾਲਤ SSH_ERR_BIGNUM_IS_NEGATIVE:
		ਵਾਪਸ "bignum is negative";
	ਹਾਲਤ SSH_ERR_STRING_TOO_LARGE:
		ਵਾਪਸ "string is too large";
	ਹਾਲਤ SSH_ERR_BIGNUM_TOO_LARGE:
		ਵਾਪਸ "bignum is too large";
	ਹਾਲਤ SSH_ERR_ECPOINT_TOO_LARGE:
		ਵਾਪਸ "elliptic curve point is too large";
	ਹਾਲਤ SSH_ERR_NO_ਬਫਰ_SPACE:
		ਵਾਪਸ "insufficient buffer space";
	ਹਾਲਤ SSH_ERR_INVALID_ਦਲੀਲ:
		ਵਾਪਸ "invalid argument";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ਬਿੱਟ_MISMATCH:
		ਵਾਪਸ "key bits do not match";
	ਹਾਲਤ SSH_ERR_EC_ਵਕਰ_INVALID:
		ਵਾਪਸ "invalid elliptic curve";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH:
		ਵਾਪਸ "key type does not match";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN:
		ਵਾਪਸ "unknown or unsupported key type";
	ਹਾਲਤ SSH_ERR_EC_ਵਕਰ_MISMATCH:
		ਵਾਪਸ "elliptic curve does not match";
	ਹਾਲਤ SSH_ERR_EXPECTED_CERT:
		ਵਾਪਸ "plain key provided where certificate required";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_LACKS_CERTBLOB:
		ਵਾਪਸ "key lacks certificate data";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_CERT_UNKNOWN_TYPE:
		ਵਾਪਸ "unknown/unsupported certificate type";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ:
		ਵਾਪਸ "invalid certificate signing key";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ:
		ਵਾਪਸ "invalid elliptic curve value";
	ਹਾਲਤ SSH_ERR_SIGNATURE_INVALID:
		ਵਾਪਸ "incorrect signature";
	ਹਾਲਤ SSH_ERR_LIBCRYPTO_ERROR:
		ਸੁਨੇਹਾ = ssherr_libcrypto();
		ਵਾਪਸ ਸੁਨੇਹਾ != ਨਿਰਾ ? ਸੁਨੇਹਾ : "error in libcrypto";
	ਹਾਲਤ SSH_ERR_ਅੰਦਰੂਨੀ_CRYPTO_ERROR:
		ਵਾਪਸ "cryptographic operation failed";
	ਹਾਲਤ SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ:
		ਵਾਪਸ "unexpected bytes remain after decoding";
	ਹਾਲਤ SSH_ERR_SYSTEM_ERROR:
		ਵਾਪਸ strerror(errno);
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID:
		ਵਾਪਸ "invalid certificate";
	ਹਾਲਤ SSH_ERR_AGENT_COMMUNICATION:
		ਵਾਪਸ "communication with agent failed";
	ਹਾਲਤ SSH_ERR_AGENT_FAILURE:
		ਵਾਪਸ "agent refused operation";
	ਹਾਲਤ SSH_ERR_DH_GEX_ਬਾਹਰਲਾ_ਦਾ_RANGE:
		ਵਾਪਸ "DH GEX group out of range";
	ਹਾਲਤ SSH_ERR_DISCONNECTED:
		ਵਾਪਸ "disconnected";
	ਹਾਲਤ SSH_ERR_MAC_INVALID:
		ਵਾਪਸ "message authentication code incorrect";
	ਹਾਲਤ SSH_ERR_NO_CIPHER_ALG_ਮੇਲ:
		ਵਾਪਸ "no matching cipher found";
	ਹਾਲਤ SSH_ERR_NO_MAC_ALG_ਮੇਲ:
		ਵਾਪਸ "no matching MAC found";
	ਹਾਲਤ SSH_ERR_NO_COMPRESS_ALG_ਮੇਲ:
		ਵਾਪਸ "no matching compression method found";
	ਹਾਲਤ SSH_ERR_NO_KEX_ALG_ਮੇਲ:
		ਵਾਪਸ "no matching key exchange method found";
	ਹਾਲਤ SSH_ERR_NO_HOSTKEY_ALG_ਮੇਲ:
		ਵਾਪਸ "no matching host key type found";
	ਹਾਲਤ SSH_ERR_PROTOCOL_MISMATCH:
		ਵਾਪਸ "protocol version mismatch";
	ਹਾਲਤ SSH_ERR_NO_PROTOCOL_ਸੰਸਕਰਣ:
		ਵਾਪਸ "could not read protocol version";
	ਹਾਲਤ SSH_ERR_NO_HOSTKEY_LOADED:
		ਵਾਪਸ "could not load host key";
	ਹਾਲਤ SSH_ERR_NEED_REKEY:
		ਵਾਪਸ "rekeying not supported by peer";
	ਹਾਲਤ SSH_ERR_PASSPHRASE_TOO_SHORT:
		ਵਾਪਸ "passphrase is too short (minimum five characters)";
	ਹਾਲਤ SSH_ERR_FILE_ਬਦਲਿਆ:
		ਵਾਪਸ "file changed while reading";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_UNKNOWN_CIPHER:
		ਵਾਪਸ "key encrypted using unsupported cipher";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE:
		ਵਾਪਸ "incorrect passphrase supplied to decrypt private key";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_BAD_PERMISSIONS:
		ਵਾਪਸ "bad permissions";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH:
		ਵਾਪਸ "certificate does not match key";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ:
		ਵਾਪਸ "key not found";
	ਹਾਲਤ SSH_ERR_AGENT_NOT_PRESENT:
		ਵਾਪਸ "agent not present";
	ਹਾਲਤ SSH_ERR_AGENT_NO_IDENTITIES:
		ਵਾਪਸ "agent contains no identities";
	ਹਾਲਤ SSH_ERR_ਬਫਰ_READ_ONLY:
		ਵਾਪਸ "internal error: buffer is read-only";
	ਹਾਲਤ SSH_ERR_KRL_BAD_MAGIC:
		ਵਾਪਸ "KRL file has invalid magic number";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_REVOKED:
		ਵਾਪਸ "Key is revoked";
	ਹਾਲਤ SSH_ERR_CONN_CLOSED:
		ਵਾਪਸ "Connection closed";
	ਹਾਲਤ SSH_ERR_CONN_TIMEOUT:
		ਵਾਪਸ "Connection timed out";
	ਹਾਲਤ SSH_ERR_CONN_CORRUPT:
		ਵਾਪਸ "Connection corrupted";
	ਹਾਲਤ SSH_ERR_PROTOCOL_ERROR:
		ਵਾਪਸ "Protocol error";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ:
		ਵਾਪਸ "Invalid key length";
	ਹਾਲਤ SSH_ERR_ਸੰਖਿਆ_TOO_LARGE:
		ਵਾਪਸ "number is too large";
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ALG_UNSUPPORTED:
		ਵਾਪਸ "key algorithm not supported";
	ਹਾਲਤ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ਵਾਪਸ "signature algorithm not supported";
	ਹਾਲਤ SSH_ERR_FEATURE_UNSUPPORTED:
		ਵਾਪਸ "requested feature not supported";
	ਹਾਲਤ SSH_ERR_DEVICE_NOT_ਮਿਲਿਆ:
		ਵਾਪਸ "device not found";
	ਮੂਲ:
		ਵਾਪਸ "unknown error";
	}
}
