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

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಧ್ರುವ ವರ್ಣ *
ssh_err(ಪೂರ್ಣಾಙ್ಕ n)
{
	ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;

	ವಿಕಲ್ಪ (n) {
	ಪಕ್ಷ SSH_ERR_SUCCESS:
		ಪ್ರತ್ಯಾಗಮ "success";
	ಪಕ್ಷ SSH_ERR_INTERNAL_ERROR:
		ಪ್ರತ್ಯಾಗಮ "unexpected internal error";
	ಪಕ್ಷ SSH_ERR_ALLOC_FAIL:
		ಪ್ರತ್ಯಾಗಮ "memory allocation failed";
	ಪಕ್ಷ SSH_ERR_MESSAGE_INCOMPLETE:
		ಪ್ರತ್ಯಾಗಮ "incomplete message";
	ಪಕ್ಷ SSH_ERR_INVALID_FORMAT:
		ಪ್ರತ್ಯಾಗಮ "invalid format";
	ಪಕ್ಷ SSH_ERR_BIGNUM_IS_NEGATIVE:
		ಪ್ರತ್ಯಾಗಮ "bignum is negative";
	ಪಕ್ಷ SSH_ERR_STRING_TOO_LARGE:
		ಪ್ರತ್ಯಾಗಮ "string is too large";
	ಪಕ್ಷ SSH_ERR_BIGNUM_TOO_LARGE:
		ಪ್ರತ್ಯಾಗಮ "bignum is too large";
	ಪಕ್ಷ SSH_ERR_ECPOINT_TOO_LARGE:
		ಪ್ರತ್ಯಾಗಮ "elliptic curve point is too large";
	ಪಕ್ಷ SSH_ERR_NO_BUFFER_SPACE:
		ಪ್ರತ್ಯಾಗಮ "insufficient buffer space";
	ಪಕ್ಷ SSH_ERR_INVALID_ARGUMENT:
		ಪ್ರತ್ಯಾಗಮ "invalid argument";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_BITS_MISMATCH:
		ಪ್ರತ್ಯಾಗಮ "key bits do not match";
	ಪಕ್ಷ SSH_ERR_EC_CURVE_INVALID:
		ಪ್ರತ್ಯಾಗಮ "invalid elliptic curve";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH:
		ಪ್ರತ್ಯಾಗಮ "key type does not match";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN:
		ಪ್ರತ್ಯಾಗಮ "unknown or unsupported key type";
	ಪಕ್ಷ SSH_ERR_EC_CURVE_MISMATCH:
		ಪ್ರತ್ಯಾಗಮ "elliptic curve does not match";
	ಪಕ್ಷ SSH_ERR_EXPECTED_CERT:
		ಪ್ರತ್ಯಾಗಮ "plain key provided where certificate required";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_LACKS_CERTBLOB:
		ಪ್ರತ್ಯಾಗಮ "key lacks certificate data";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_CERT_UNKNOWN_TYPE:
		ಪ್ರತ್ಯಾಗಮ "unknown/unsupported certificate type";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ:
		ಪ್ರತ್ಯಾಗಮ "invalid certificate signing key";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ:
		ಪ್ರತ್ಯಾಗಮ "invalid elliptic curve value";
	ಪಕ್ಷ SSH_ERR_SIGNATURE_INVALID:
		ಪ್ರತ್ಯಾಗಮ "incorrect signature";
	ಪಕ್ಷ SSH_ERR_LIBCRYPTO_ERROR:
		ಸಂದೇಶ = ssherr_libcrypto();
		ಪ್ರತ್ಯಾಗಮ ಸಂದೇಶ != ರಿಕ್ತ ? ಸಂದೇಶ : "error in libcrypto";
	ಪಕ್ಷ SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ಪ್ರತ್ಯಾಗಮ "cryptographic operation failed";
	ಪಕ್ಷ SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ಪ್ರತ್ಯಾಗಮ "unexpected bytes remain after decoding";
	ಪಕ್ಷ SSH_ERR_SYSTEM_ERROR:
		ಪ್ರತ್ಯಾಗಮ strerror(errno);
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_CERT_INVALID:
		ಪ್ರತ್ಯಾಗಮ "invalid certificate";
	ಪಕ್ಷ SSH_ERR_AGENT_COMMUNICATION:
		ಪ್ರತ್ಯಾಗಮ "communication with agent failed";
	ಪಕ್ಷ SSH_ERR_AGENT_FAILURE:
		ಪ್ರತ್ಯಾಗಮ "agent refused operation";
	ಪಕ್ಷ SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ಪ್ರತ್ಯಾಗಮ "DH GEX group out of range";
	ಪಕ್ಷ SSH_ERR_DISCONNECTED:
		ಪ್ರತ್ಯಾಗಮ "disconnected";
	ಪಕ್ಷ SSH_ERR_MAC_INVALID:
		ಪ್ರತ್ಯಾಗಮ "message authentication code incorrect";
	ಪಕ್ಷ SSH_ERR_NO_CIPHER_ALG_MATCH:
		ಪ್ರತ್ಯಾಗಮ "no matching cipher found";
	ಪಕ್ಷ SSH_ERR_NO_MAC_ALG_MATCH:
		ಪ್ರತ್ಯಾಗಮ "no matching MAC found";
	ಪಕ್ಷ SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ಪ್ರತ್ಯಾಗಮ "no matching compression method found";
	ಪಕ್ಷ SSH_ERR_NO_KEX_ALG_MATCH:
		ಪ್ರತ್ಯಾಗಮ "no matching key exchange method found";
	ಪಕ್ಷ SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ಪ್ರತ್ಯಾಗಮ "no matching host key type found";
	ಪಕ್ಷ SSH_ERR_PROTOCOL_MISMATCH:
		ಪ್ರತ್ಯಾಗಮ "protocol version mismatch";
	ಪಕ್ಷ SSH_ERR_NO_PROTOCOL_VERSION:
		ಪ್ರತ್ಯಾಗಮ "could not read protocol version";
	ಪಕ್ಷ SSH_ERR_NO_HOSTKEY_LOADED:
		ಪ್ರತ್ಯಾಗಮ "could not load host key";
	ಪಕ್ಷ SSH_ERR_NEED_REKEY:
		ಪ್ರತ್ಯಾಗಮ "rekeying not supported by peer";
	ಪಕ್ಷ SSH_ERR_PASSPHRASE_TOO_SHORT:
		ಪ್ರತ್ಯಾಗಮ "passphrase is too short (minimum five characters)";
	ಪಕ್ಷ SSH_ERR_FILE_CHANGED:
		ಪ್ರತ್ಯಾಗಮ "file changed while reading";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER:
		ಪ್ರತ್ಯಾಗಮ "key encrypted using unsupported cipher";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE:
		ಪ್ರತ್ಯಾಗಮ "incorrect passphrase supplied to decrypt private key";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS:
		ಪ್ರತ್ಯಾಗಮ "bad permissions";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_CERT_MISMATCH:
		ಪ್ರತ್ಯಾಗಮ "certificate does not match key";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_NOT_FOUND:
		ಪ್ರತ್ಯಾಗಮ "key not found";
	ಪಕ್ಷ SSH_ERR_AGENT_NOT_PRESENT:
		ಪ್ರತ್ಯಾಗಮ "agent not present";
	ಪಕ್ಷ SSH_ERR_AGENT_NO_IDENTITIES:
		ಪ್ರತ್ಯಾಗಮ "agent contains no identities";
	ಪಕ್ಷ SSH_ERR_BUFFER_READ_ONLY:
		ಪ್ರತ್ಯಾಗಮ "internal error: buffer is read-only";
	ಪಕ್ಷ SSH_ERR_KRL_BAD_MAGIC:
		ಪ್ರತ್ಯಾಗಮ "KRL file has invalid magic number";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_REVOKED:
		ಪ್ರತ್ಯಾಗಮ "Key is revoked";
	ಪಕ್ಷ SSH_ERR_CONN_CLOSED:
		ಪ್ರತ್ಯಾಗಮ "Connection closed";
	ಪಕ್ಷ SSH_ERR_CONN_TIMEOUT:
		ಪ್ರತ್ಯಾಗಮ "Connection timed out";
	ಪಕ್ಷ SSH_ERR_CONN_CORRUPT:
		ಪ್ರತ್ಯಾಗಮ "Connection corrupted";
	ಪಕ್ಷ SSH_ERR_PROTOCOL_ERROR:
		ಪ್ರತ್ಯಾಗಮ "Protocol error";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_LENGTH:
		ಪ್ರತ್ಯಾಗಮ "Invalid key length";
	ಪಕ್ಷ SSH_ERR_ಸಂಖ್ಯೆ_TOO_LARGE:
		ಪ್ರತ್ಯಾಗಮ "number is too large";
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		ಪ್ರತ್ಯಾಗಮ "key algorithm not supported";
	ಪಕ್ಷ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ಪ್ರತ್ಯಾಗಮ "signature algorithm not supported";
	ಪಕ್ಷ SSH_ERR_FEATURE_UNSUPPORTED:
		ಪ್ರತ್ಯಾಗಮ "requested feature not supported";
	ಪಕ್ಷ SSH_ERR_DEVICE_NOT_FOUND:
		ಪ್ರತ್ಯಾಗಮ "device not found";
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ "unknown error";
	}
}
