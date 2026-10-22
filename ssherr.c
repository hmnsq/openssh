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

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_err(ಪೂರ್ಣಾಂಕ n)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;

	ಆಯ್ಕೆ (n) {
	ಸ್ಥಿತಿ SSH_ERR_SUCCESS:
		ಹಿಂತಿರುಗಿ "success";
	ಸ್ಥಿತಿ SSH_ERR_ಆಂತರಿಕ_ERROR:
		ಹಿಂತಿರುಗಿ "unexpected internal error";
	ಸ್ಥಿತಿ SSH_ERR_ALLOC_FAIL:
		ಹಿಂತಿರುಗಿ "memory allocation failed";
	ಸ್ಥಿತಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE:
		ಹಿಂತಿರುಗಿ "incomplete message";
	ಸ್ಥಿತಿ SSH_ERR_INVALID_FORMAT:
		ಹಿಂತಿರುಗಿ "invalid format";
	ಸ್ಥಿತಿ SSH_ERR_BIGNUM_IS_NEGATIVE:
		ಹಿಂತಿರುಗಿ "bignum is negative";
	ಸ್ಥಿತಿ SSH_ERR_STRING_TOO_LARGE:
		ಹಿಂತಿರುಗಿ "string is too large";
	ಸ್ಥಿತಿ SSH_ERR_BIGNUM_TOO_LARGE:
		ಹಿಂತಿರುಗಿ "bignum is too large";
	ಸ್ಥಿತಿ SSH_ERR_ECPOINT_TOO_LARGE:
		ಹಿಂತಿರುಗಿ "elliptic curve point is too large";
	ಸ್ಥಿತಿ SSH_ERR_NO_ಬಫರ್_SPACE:
		ಹಿಂತಿರುಗಿ "insufficient buffer space";
	ಸ್ಥಿತಿ SSH_ERR_INVALID_ವಾದ:
		ಹಿಂತಿರುಗಿ "invalid argument";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ಬಿಟ್ಟುಗಳು_MISMATCH:
		ಹಿಂತಿರುಗಿ "key bits do not match";
	ಸ್ಥಿತಿ SSH_ERR_EC_ವಕ್ರ_INVALID:
		ಹಿಂತಿರುಗಿ "invalid elliptic curve";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH:
		ಹಿಂತಿರುಗಿ "key type does not match";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN:
		ಹಿಂತಿರುಗಿ "unknown or unsupported key type";
	ಸ್ಥಿತಿ SSH_ERR_EC_ವಕ್ರ_MISMATCH:
		ಹಿಂತಿರುಗಿ "elliptic curve does not match";
	ಸ್ಥಿತಿ SSH_ERR_EXPECTED_CERT:
		ಹಿಂತಿರುಗಿ "plain key provided where certificate required";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_LACKS_CERTBLOB:
		ಹಿಂತಿರುಗಿ "key lacks certificate data";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_CERT_UNKNOWN_TYPE:
		ಹಿಂತಿರುಗಿ "unknown/unsupported certificate type";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ:
		ಹಿಂತಿರುಗಿ "invalid certificate signing key";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ:
		ಹಿಂತಿರುಗಿ "invalid elliptic curve value";
	ಸ್ಥಿತಿ SSH_ERR_SIGNATURE_INVALID:
		ಹಿಂತಿರುಗಿ "incorrect signature";
	ಸ್ಥಿತಿ SSH_ERR_LIBCRYPTO_ERROR:
		ಸಂದೇಶ = ssherr_libcrypto();
		ಹಿಂತಿರುಗಿ ಸಂದೇಶ != ಖಾಲಿ ? ಸಂದೇಶ : "error in libcrypto";
	ಸ್ಥಿತಿ SSH_ERR_ಆಂತರಿಕ_CRYPTO_ERROR:
		ಹಿಂತಿರುಗಿ "cryptographic operation failed";
	ಸ್ಥಿತಿ SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ:
		ಹಿಂತಿರುಗಿ "unexpected bytes remain after decoding";
	ಸ್ಥಿತಿ SSH_ERR_SYSTEM_ERROR:
		ಹಿಂತಿರುಗಿ strerror(errno);
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID:
		ಹಿಂತಿರುಗಿ "invalid certificate";
	ಸ್ಥಿತಿ SSH_ERR_AGENT_COMMUNICATION:
		ಹಿಂತಿರುಗಿ "communication with agent failed";
	ಸ್ಥಿತಿ SSH_ERR_AGENT_FAILURE:
		ಹಿಂತಿರುಗಿ "agent refused operation";
	ಸ್ಥಿತಿ SSH_ERR_DH_GEX_ಹೊರಹೋಗು_ದ_RANGE:
		ಹಿಂತಿರುಗಿ "DH GEX group out of range";
	ಸ್ಥಿತಿ SSH_ERR_DISCONNECTED:
		ಹಿಂತಿರುಗಿ "disconnected";
	ಸ್ಥಿತಿ SSH_ERR_MAC_INVALID:
		ಹಿಂತಿರುಗಿ "message authentication code incorrect";
	ಸ್ಥಿತಿ SSH_ERR_NO_CIPHER_ALG_ಹೊಂದಿಕೆ:
		ಹಿಂತಿರುಗಿ "no matching cipher found";
	ಸ್ಥಿತಿ SSH_ERR_NO_MAC_ALG_ಹೊಂದಿಕೆ:
		ಹಿಂತಿರುಗಿ "no matching MAC found";
	ಸ್ಥಿತಿ SSH_ERR_NO_COMPRESS_ALG_ಹೊಂದಿಕೆ:
		ಹಿಂತಿರುಗಿ "no matching compression method found";
	ಸ್ಥಿತಿ SSH_ERR_NO_KEX_ALG_ಹೊಂದಿಕೆ:
		ಹಿಂತಿರುಗಿ "no matching key exchange method found";
	ಸ್ಥಿತಿ SSH_ERR_NO_HOSTKEY_ALG_ಹೊಂದಿಕೆ:
		ಹಿಂತಿರುಗಿ "no matching host key type found";
	ಸ್ಥಿತಿ SSH_ERR_PROTOCOL_MISMATCH:
		ಹಿಂತಿರುಗಿ "protocol version mismatch";
	ಸ್ಥಿತಿ SSH_ERR_NO_PROTOCOL_ಆವೃತ್ತಿ:
		ಹಿಂತಿರುಗಿ "could not read protocol version";
	ಸ್ಥಿತಿ SSH_ERR_NO_HOSTKEY_LOADED:
		ಹಿಂತಿರುಗಿ "could not load host key";
	ಸ್ಥಿತಿ SSH_ERR_NEED_REKEY:
		ಹಿಂತಿರುಗಿ "rekeying not supported by peer";
	ಸ್ಥಿತಿ SSH_ERR_PASSPHRASE_TOO_SHORT:
		ಹಿಂತಿರುಗಿ "passphrase is too short (minimum five characters)";
	ಸ್ಥಿತಿ SSH_ERR_FILE_ಬದಲಾಯಿತು:
		ಹಿಂತಿರುಗಿ "file changed while reading";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER:
		ಹಿಂತಿರುಗಿ "key encrypted using unsupported cipher";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE:
		ಹಿಂತಿರುಗಿ "incorrect passphrase supplied to decrypt private key";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS:
		ಹಿಂತಿರುಗಿ "bad permissions";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_CERT_MISMATCH:
		ಹಿಂತಿರುಗಿ "certificate does not match key";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು:
		ಹಿಂತಿರುಗಿ "key not found";
	ಸ್ಥಿತಿ SSH_ERR_AGENT_NOT_PRESENT:
		ಹಿಂತಿರುಗಿ "agent not present";
	ಸ್ಥಿತಿ SSH_ERR_AGENT_NO_IDENTITIES:
		ಹಿಂತಿರುಗಿ "agent contains no identities";
	ಸ್ಥಿತಿ SSH_ERR_ಬಫರ್_READ_ONLY:
		ಹಿಂತಿರುಗಿ "internal error: buffer is read-only";
	ಸ್ಥಿತಿ SSH_ERR_KRL_BAD_MAGIC:
		ಹಿಂತಿರುಗಿ "KRL file has invalid magic number";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_REVOKED:
		ಹಿಂತಿರುಗಿ "Key is revoked";
	ಸ್ಥಿತಿ SSH_ERR_CONN_CLOSED:
		ಹಿಂತಿರುಗಿ "Connection closed";
	ಸ್ಥಿತಿ SSH_ERR_CONN_TIMEOUT:
		ಹಿಂತಿರುಗಿ "Connection timed out";
	ಸ್ಥಿತಿ SSH_ERR_CONN_CORRUPT:
		ಹಿಂತಿರುಗಿ "Connection corrupted";
	ಸ್ಥಿತಿ SSH_ERR_PROTOCOL_ERROR:
		ಹಿಂತಿರುಗಿ "Protocol error";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ:
		ಹಿಂತಿರುಗಿ "Invalid key length";
	ಸ್ಥಿತಿ SSH_ERR_ಸಂಖ್ಯೆ_TOO_LARGE:
		ಹಿಂತಿರುಗಿ "number is too large";
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED:
		ಹಿಂತಿರುಗಿ "key algorithm not supported";
	ಸ್ಥಿತಿ SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ಹಿಂತಿರುಗಿ "signature algorithm not supported";
	ಸ್ಥಿತಿ SSH_ERR_FEATURE_UNSUPPORTED:
		ಹಿಂತಿರುಗಿ "requested feature not supported";
	ಸ್ಥಿತಿ SSH_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು:
		ಹಿಂತಿರುಗಿ "device not found";
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ "unknown error";
	}
}
