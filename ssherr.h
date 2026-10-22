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

#اگر_غیر_تعریف_شدہ _SSHERR_H
#تعریف_کرو _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#تعریف_کرو SSH_ERR_SUCCESS				0
#تعریف_کرو SSH_ERR_اندرونی_ERROR			-1
#تعریف_کرو SSH_ERR_ALLOC_FAIL			-2
#تعریف_کرو SSH_ERR_پیغام_INCOMPLETE		-3
#تعریف_کرو SSH_ERR_INVALID_FORMAT			-4
#تعریف_کرو SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#تعریف_کرو SSH_ERR_STRING_TOO_LARGE		-6
#تعریف_کرو SSH_ERR_BIGNUM_TOO_LARGE		-7
#تعریف_کرو SSH_ERR_ECPOINT_TOO_LARGE		-8
#تعریف_کرو SSH_ERR_NO_بفر_SPACE			-9
#تعریف_کرو SSH_ERR_INVALID_دلیل		-10
#تعریف_کرو SSH_ERR_کلید_بٹ_MISMATCH		-11
#تعریف_کرو SSH_ERR_EC_خم_INVALID		-12
#تعریف_کرو SSH_ERR_کلید_TYPE_MISMATCH		-13
#تعریف_کرو SSH_ERR_کلید_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#تعریف_کرو SSH_ERR_EC_خم_MISMATCH		-15
#تعریف_کرو SSH_ERR_EXPECTED_CERT			-16
#تعریف_کرو SSH_ERR_کلید_LACKS_CERTBLOB		-17
#تعریف_کرو SSH_ERR_کلید_CERT_UNKNOWN_TYPE		-18
#تعریف_کرو SSH_ERR_کلید_CERT_INVALID_SIGN_کلید	-19
#تعریف_کرو SSH_ERR_کلید_INVALID_EC_قدر		-20
#تعریف_کرو SSH_ERR_SIGNATURE_INVALID		-21
#تعریف_کرو SSH_ERR_LIBCRYPTO_ERROR			-22
#تعریف_کرو SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا	-23
#تعریف_کرو SSH_ERR_SYSTEM_ERROR			-24
#تعریف_کرو SSH_ERR_کلید_CERT_INVALID		-25
#تعریف_کرو SSH_ERR_AGENT_COMMUNICATION		-26
#تعریف_کرو SSH_ERR_AGENT_FAILURE			-27
#تعریف_کرو SSH_ERR_DH_GEX_برآمد_کا_RANGE		-28
#تعریف_کرو SSH_ERR_DISCONNECTED			-29
#تعریف_کرو SSH_ERR_MAC_INVALID			-30
#تعریف_کرو SSH_ERR_NO_CIPHER_ALG_مطابقت		-31
#تعریف_کرو SSH_ERR_NO_MAC_ALG_مطابقت		-32
#تعریف_کرو SSH_ERR_NO_COMPRESS_ALG_مطابقت		-33
#تعریف_کرو SSH_ERR_NO_KEX_ALG_مطابقت		-34
#تعریف_کرو SSH_ERR_NO_HOSTKEY_ALG_مطابقت		-35
#تعریف_کرو SSH_ERR_NO_HOSTKEY_LOADED		-36
#تعریف_کرو SSH_ERR_PROTOCOL_MISMATCH		-37
#تعریف_کرو SSH_ERR_NO_PROTOCOL_نسخہ		-38
#تعریف_کرو SSH_ERR_NEED_REKEY			-39
#تعریف_کرو SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#تعریف_کرو SSH_ERR_FILE_بدلا			-41
#تعریف_کرو SSH_ERR_کلید_UNKNOWN_CIPHER		-42
#تعریف_کرو SSH_ERR_کلید_WRONG_PASSPHRASE		-43
#تعریف_کرو SSH_ERR_کلید_BAD_PERMISSIONS		-44
#تعریف_کرو SSH_ERR_کلید_CERT_MISMATCH		-45
#تعریف_کرو SSH_ERR_کلید_NOT_ملا			-46
#تعریف_کرو SSH_ERR_AGENT_NOT_PRESENT		-47
#تعریف_کرو SSH_ERR_AGENT_NO_IDENTITIES		-48
#تعریف_کرو SSH_ERR_بفر_READ_ONLY		-49
#تعریف_کرو SSH_ERR_KRL_BAD_MAGIC			-50
#تعریف_کرو SSH_ERR_کلید_REVOKED			-51
#تعریف_کرو SSH_ERR_CONN_CLOSED			-52
#تعریف_کرو SSH_ERR_CONN_TIMEOUT			-53
#تعریف_کرو SSH_ERR_CONN_CORRUPT			-54
#تعریف_کرو SSH_ERR_PROTOCOL_ERROR			-55
#تعریف_کرو SSH_ERR_کلید_لمبائی			-56
#تعریف_کرو SSH_ERR_نمبر_TOO_LARGE		-57
#تعریف_کرو SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#تعریف_کرو SSH_ERR_FEATURE_UNSUPPORTED		-59
#تعریف_کرو SSH_ERR_DEVICE_NOT_ملا		-60
#تعریف_کرو SSH_ERR_CRYPTO_ERROR			-61
#تعریف_کرو SSH_ERR_اندرونی_CRYPTO_ERROR		-62
#تعریف_کرو SSH_ERR_کلید_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
ثابت حرف *ssh_err(صحیح n);
/* Return most recent error from libcrypto. */
ثابت حرف *ssherr_libcrypto(خالی);

#اگر_ختم /* _SSHERR_H */
