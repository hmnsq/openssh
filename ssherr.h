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

#جيڪڏهن_وصف_نه_ٿيل _SSHERR_H
#وصف_ڪريو _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#وصف_ڪريو SSH_ERR_SUCCESS				0
#وصف_ڪريو SSH_ERR_اندروني_ERROR			-1
#وصف_ڪريو SSH_ERR_ALLOC_FAIL			-2
#وصف_ڪريو SSH_ERR_پيغام_INCOMPLETE		-3
#وصف_ڪريو SSH_ERR_INVALID_FORMAT			-4
#وصف_ڪريو SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#وصف_ڪريو SSH_ERR_STRING_TOO_LARGE		-6
#وصف_ڪريو SSH_ERR_BIGNUM_TOO_LARGE		-7
#وصف_ڪريو SSH_ERR_ECPOINT_TOO_LARGE		-8
#وصف_ڪريو SSH_ERR_NO_بفر_SPACE			-9
#وصف_ڪريو SSH_ERR_INVALID_دليل		-10
#وصف_ڪريو SSH_ERR_ڪنجي_بٽ_MISMATCH		-11
#وصف_ڪريو SSH_ERR_EC_وڪر_INVALID		-12
#وصف_ڪريو SSH_ERR_ڪنجي_TYPE_MISMATCH		-13
#وصف_ڪريو SSH_ERR_ڪنجي_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#وصف_ڪريو SSH_ERR_EC_وڪر_MISMATCH		-15
#وصف_ڪريو SSH_ERR_EXPECTED_CERT			-16
#وصف_ڪريو SSH_ERR_ڪنجي_LACKS_CERTBLOB		-17
#وصف_ڪريو SSH_ERR_ڪنجي_CERT_UNKNOWN_TYPE		-18
#وصف_ڪريو SSH_ERR_ڪنجي_CERT_INVALID_SIGN_ڪنجي	-19
#وصف_ڪريو SSH_ERR_ڪنجي_INVALID_EC_قدر		-20
#وصف_ڪريو SSH_ERR_SIGNATURE_INVALID		-21
#وصف_ڪريو SSH_ERR_LIBCRYPTO_ERROR			-22
#وصف_ڪريو SSH_ERR_UNEXPECTED_TRAILING_معلومات	-23
#وصف_ڪريو SSH_ERR_SYSTEM_ERROR			-24
#وصف_ڪريو SSH_ERR_ڪنجي_CERT_INVALID		-25
#وصف_ڪريو SSH_ERR_AGENT_COMMUNICATION		-26
#وصف_ڪريو SSH_ERR_AGENT_FAILURE			-27
#وصف_ڪريو SSH_ERR_DH_GEX_ٻاهريون_جو_RANGE		-28
#وصف_ڪريو SSH_ERR_DISCONNECTED			-29
#وصف_ڪريو SSH_ERR_MAC_INVALID			-30
#وصف_ڪريو SSH_ERR_NO_CIPHER_ALG_ميلاپ		-31
#وصف_ڪريو SSH_ERR_NO_MAC_ALG_ميلاپ		-32
#وصف_ڪريو SSH_ERR_NO_COMPRESS_ALG_ميلاپ		-33
#وصف_ڪريو SSH_ERR_NO_KEX_ALG_ميلاپ		-34
#وصف_ڪريو SSH_ERR_NO_HOSTKEY_ALG_ميلاپ		-35
#وصف_ڪريو SSH_ERR_NO_HOSTKEY_LOADED		-36
#وصف_ڪريو SSH_ERR_PROTOCOL_MISMATCH		-37
#وصف_ڪريو SSH_ERR_NO_PROTOCOL_نسخو		-38
#وصف_ڪريو SSH_ERR_NEED_REKEY			-39
#وصف_ڪريو SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#وصف_ڪريو SSH_ERR_FILE_بدليو			-41
#وصف_ڪريو SSH_ERR_ڪنجي_UNKNOWN_CIPHER		-42
#وصف_ڪريو SSH_ERR_ڪنجي_WRONG_PASSPHRASE		-43
#وصف_ڪريو SSH_ERR_ڪنجي_BAD_PERMISSIONS		-44
#وصف_ڪريو SSH_ERR_ڪنجي_CERT_MISMATCH		-45
#وصف_ڪريو SSH_ERR_ڪنجي_NOT_مليو			-46
#وصف_ڪريو SSH_ERR_AGENT_NOT_PRESENT		-47
#وصف_ڪريو SSH_ERR_AGENT_NO_IDENTITIES		-48
#وصف_ڪريو SSH_ERR_بفر_READ_ONLY		-49
#وصف_ڪريو SSH_ERR_KRL_BAD_MAGIC			-50
#وصف_ڪريو SSH_ERR_ڪنجي_REVOKED			-51
#وصف_ڪريو SSH_ERR_CONN_CLOSED			-52
#وصف_ڪريو SSH_ERR_CONN_TIMEOUT			-53
#وصف_ڪريو SSH_ERR_CONN_CORRUPT			-54
#وصف_ڪريو SSH_ERR_PROTOCOL_ERROR			-55
#وصف_ڪريو SSH_ERR_ڪنجي_ڊيگهائي			-56
#وصف_ڪريو SSH_ERR_عدد_TOO_LARGE		-57
#وصف_ڪريو SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#وصف_ڪريو SSH_ERR_FEATURE_UNSUPPORTED		-59
#وصف_ڪريو SSH_ERR_DEVICE_NOT_مليو		-60
#وصف_ڪريو SSH_ERR_CRYPTO_ERROR			-61
#وصف_ڪريو SSH_ERR_اندروني_CRYPTO_ERROR		-62
#وصف_ڪريو SSH_ERR_ڪنجي_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
ثابت حرف *ssh_err(صحيح n);
/* Return most recent error from libcrypto. */
ثابت حرف *ssherr_libcrypto(فراغ);

#جيڪڏهن_پورو /* _SSHERR_H */
