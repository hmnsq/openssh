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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SSHERR_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_SUCCESS				0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR			-1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ALLOC_FAIL			-2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE		-3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_INVALID_FORMAT			-4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_STRING_TOO_LARGE		-6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_BIGNUM_TOO_LARGE		-7
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ECPOINT_TOO_LARGE		-8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_ਬਫਰ_SPACE			-9
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_INVALID_ਦਲੀਲ		-10
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_ਬਿੱਟ_MISMATCH		-11
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_EC_ਵਕਰ_INVALID		-12
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH		-13
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_EC_ਵਕਰ_MISMATCH		-15
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_EXPECTED_CERT			-16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_LACKS_CERTBLOB		-17
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_CERT_UNKNOWN_TYPE		-18
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ	-19
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ		-20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_SIGNATURE_INVALID		-21
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_LIBCRYPTO_ERROR			-22
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ	-23
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_SYSTEM_ERROR			-24
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID		-25
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_AGENT_COMMUNICATION		-26
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_AGENT_FAILURE			-27
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_DH_GEX_ਬਾਹਰਲਾ_ਦਾ_RANGE		-28
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_DISCONNECTED			-29
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_MAC_INVALID			-30
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_CIPHER_ALG_ਮੇਲ		-31
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_MAC_ALG_ਮੇਲ		-32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_COMPRESS_ALG_ਮੇਲ		-33
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_KEX_ALG_ਮੇਲ		-34
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_HOSTKEY_ALG_ਮੇਲ		-35
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_HOSTKEY_LOADED		-36
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_PROTOCOL_MISMATCH		-37
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NO_PROTOCOL_ਸੰਸਕਰਣ		-38
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_NEED_REKEY			-39
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_FILE_ਬਦਲਿਆ			-41
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_UNKNOWN_CIPHER		-42
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE		-43
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_BAD_PERMISSIONS		-44
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH		-45
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ			-46
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_AGENT_NOT_PRESENT		-47
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_AGENT_NO_IDENTITIES		-48
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਬਫਰ_READ_ONLY		-49
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_KRL_BAD_MAGIC			-50
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_REVOKED			-51
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_CONN_CLOSED			-52
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_CONN_TIMEOUT			-53
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_CONN_CORRUPT			-54
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_PROTOCOL_ERROR			-55
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ			-56
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਸੰਖਿਆ_TOO_LARGE		-57
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_FEATURE_UNSUPPORTED		-59
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_DEVICE_NOT_ਮਿਲਿਆ		-60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_CRYPTO_ERROR			-61
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਅੰਦਰੂਨੀ_CRYPTO_ERROR		-62
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ERR_ਕੁੰਜੀ_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
ਅਚਲ ਅੱਖਰ *ssh_err(ਪੂਰਨ n);
/* Return most recent error from libcrypto. */
ਅਚਲ ਅੱਖਰ *ssherr_libcrypto(ਖਾਲੀ);

#ਜੇ_ਅੰਤ /* _SSHERR_H */
