/*	$OpenBSD: ssherr.h,v 1.11 2026/09/16 00:31:27 djm Exp $	*/
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SSHERR_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_SUCCESS				0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಆಂತರಿಕ_ERROR			-1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ALLOC_FAIL			-2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಸಂದೇಶ_INCOMPLETE		-3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_INVALID_FORMAT			-4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_STRING_TOO_LARGE		-6
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_BIGNUM_TOO_LARGE		-7
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ECPOINT_TOO_LARGE		-8
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_ಬಫರ್_SPACE			-9
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_INVALID_ವಾದ		-10
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_ಬಿಟ್ಟುಗಳು_MISMATCH		-11
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_EC_ವಕ್ರ_INVALID		-12
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH		-13
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_EC_ವಕ್ರ_MISMATCH		-15
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_EXPECTED_CERT			-16
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_LACKS_CERTBLOB		-17
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_CERT_UNKNOWN_TYPE		-18
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ	-19
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ		-20
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_SIGNATURE_INVALID		-21
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_LIBCRYPTO_ERROR			-22
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ	-23
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_SYSTEM_ERROR			-24
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_CERT_INVALID		-25
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_AGENT_COMMUNICATION		-26
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_AGENT_FAILURE			-27
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_DH_GEX_ಹೊರಹೋಗು_ದ_RANGE		-28
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_DISCONNECTED			-29
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_MAC_INVALID			-30
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_CIPHER_ALG_ಹೊಂದಿಕೆ		-31
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_MAC_ALG_ಹೊಂದಿಕೆ		-32
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_COMPRESS_ALG_ಹೊಂದಿಕೆ		-33
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_KEX_ALG_ಹೊಂದಿಕೆ		-34
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_HOSTKEY_ALG_ಹೊಂದಿಕೆ		-35
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_HOSTKEY_LOADED		-36
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_PROTOCOL_MISMATCH		-37
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NO_PROTOCOL_ಆವೃತ್ತಿ		-38
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_NEED_REKEY			-39
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_FILE_ಬದಲಾಯಿತು			-41
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER		-42
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE		-43
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS		-44
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_CERT_MISMATCH		-45
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು			-46
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_AGENT_NOT_PRESENT		-47
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_AGENT_NO_IDENTITIES		-48
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಬಫರ್_READ_ONLY		-49
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_KRL_BAD_MAGIC			-50
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_REVOKED			-51
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_CONN_CLOSED			-52
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_CONN_TIMEOUT			-53
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_CONN_CORRUPT			-54
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_PROTOCOL_ERROR			-55
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ			-56
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಸಂಖ್ಯೆ_TOO_LARGE		-57
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_FEATURE_UNSUPPORTED		-59
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು		-60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_CRYPTO_ERROR			-61
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಆಂತರಿಕ_CRYPTO_ERROR		-62
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_err(ಪೂರ್ಣಾಂಕ n);
/* Return most recent error from libcrypto. */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssherr_libcrypto(ಶೂನ್ಯ);

#ಆದರೆ_ಅಂತ್ಯ /* _SSHERR_H */
