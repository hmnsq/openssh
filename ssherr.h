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

#अगर_अघोषित _SSHERR_H
#घोषणा _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#घोषणा SSH_ERR_SUCCESS				0
#घोषणा SSH_ERR_INTERNAL_ERROR			-1
#घोषणा SSH_ERR_ALLOC_FAIL			-2
#घोषणा SSH_ERR_MESSAGE_INCOMPLETE		-3
#घोषणा SSH_ERR_INVALID_FORMAT			-4
#घोषणा SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#घोषणा SSH_ERR_STRING_TOO_LARGE		-6
#घोषणा SSH_ERR_BIGNUM_TOO_LARGE		-7
#घोषणा SSH_ERR_ECPOINT_TOO_LARGE		-8
#घोषणा SSH_ERR_NO_बफर_SPACE			-9
#घोषणा SSH_ERR_INVALID_ARGUMENT		-10
#घोषणा SSH_ERR_कुंजी_BITS_MISMATCH		-11
#घोषणा SSH_ERR_EC_CURVE_INVALID		-12
#घोषणा SSH_ERR_कुंजी_TYPE_MISMATCH		-13
#घोषणा SSH_ERR_कुंजी_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#घोषणा SSH_ERR_EC_CURVE_MISMATCH		-15
#घोषणा SSH_ERR_EXPECTED_CERT			-16
#घोषणा SSH_ERR_कुंजी_LACKS_CERTBLOB		-17
#घोषणा SSH_ERR_कुंजी_CERT_UNKNOWN_TYPE		-18
#घोषणा SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी	-19
#घोषणा SSH_ERR_कुंजी_INVALID_EC_मूल्य		-20
#घोषणा SSH_ERR_SIGNATURE_INVALID		-21
#घोषणा SSH_ERR_LIBCRYPTO_ERROR			-22
#घोषणा SSH_ERR_UNEXPECTED_TRAILING_तथ्य	-23
#घोषणा SSH_ERR_SYSTEM_ERROR			-24
#घोषणा SSH_ERR_कुंजी_CERT_INVALID		-25
#घोषणा SSH_ERR_AGENT_COMMUNICATION		-26
#घोषणा SSH_ERR_AGENT_FAILURE			-27
#घोषणा SSH_ERR_DH_GEX_OUT_OF_RANGE		-28
#घोषणा SSH_ERR_DISCONNECTED			-29
#घोषणा SSH_ERR_MAC_INVALID			-30
#घोषणा SSH_ERR_NO_CIPHER_ALG_MATCH		-31
#घोषणा SSH_ERR_NO_MAC_ALG_MATCH		-32
#घोषणा SSH_ERR_NO_COMPRESS_ALG_MATCH		-33
#घोषणा SSH_ERR_NO_KEX_ALG_MATCH		-34
#घोषणा SSH_ERR_NO_HOSTKEY_ALG_MATCH		-35
#घोषणा SSH_ERR_NO_HOSTKEY_LOADED		-36
#घोषणा SSH_ERR_PROTOCOL_MISMATCH		-37
#घोषणा SSH_ERR_NO_PROTOCOL_VERSION		-38
#घोषणा SSH_ERR_NEED_REKEY			-39
#घोषणा SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#घोषणा SSH_ERR_FILE_CHANGED			-41
#घोषणा SSH_ERR_कुंजी_UNKNOWN_CIPHER		-42
#घोषणा SSH_ERR_कुंजी_WRONG_PASSPHRASE		-43
#घोषणा SSH_ERR_कुंजी_BAD_PERMISSIONS		-44
#घोषणा SSH_ERR_कुंजी_CERT_MISMATCH		-45
#घोषणा SSH_ERR_कुंजी_NOT_FOUND			-46
#घोषणा SSH_ERR_AGENT_NOT_PRESENT		-47
#घोषणा SSH_ERR_AGENT_NO_IDENTITIES		-48
#घोषणा SSH_ERR_बफर_READ_ONLY		-49
#घोषणा SSH_ERR_KRL_BAD_MAGIC			-50
#घोषणा SSH_ERR_कुंजी_REVOKED			-51
#घोषणा SSH_ERR_CONN_CLOSED			-52
#घोषणा SSH_ERR_CONN_TIMEOUT			-53
#घोषणा SSH_ERR_CONN_CORRUPT			-54
#घोषणा SSH_ERR_PROTOCOL_ERROR			-55
#घोषणा SSH_ERR_कुंजी_लंबाई			-56
#घोषणा SSH_ERR_संख्या_TOO_LARGE		-57
#घोषणा SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#घोषणा SSH_ERR_FEATURE_UNSUPPORTED		-59
#घोषणा SSH_ERR_DEVICE_NOT_FOUND		-60
#घोषणा SSH_ERR_CRYPTO_ERROR			-61
#घोषणा SSH_ERR_INTERNAL_CRYPTO_ERROR		-62
#घोषणा SSH_ERR_कुंजी_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
स्थिर अक्षर *ssh_err(पूर्णांक n);
/* Return most recent error from libcrypto. */
स्थिर अक्षर *ssherr_libcrypto(व्योम);

#पूर्ण_अगर /* _SSHERR_H */
