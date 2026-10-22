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

#यदि_अपरिभाषितम् _SSHERR_H
#परिभाषय _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#परिभाषय SSH_ERR_SUCCESS				0
#परिभाषय SSH_ERR_आन्तरिकम्_ERROR			-1
#परिभाषय SSH_ERR_ALLOC_FAIL			-2
#परिभाषय SSH_ERR_सन्देशः_INCOMPLETE		-3
#परिभाषय SSH_ERR_INVALID_FORMAT			-4
#परिभाषय SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#परिभाषय SSH_ERR_STRING_TOO_LARGE		-6
#परिभाषय SSH_ERR_BIGNUM_TOO_LARGE		-7
#परिभाषय SSH_ERR_ECPOINT_TOO_LARGE		-8
#परिभाषय SSH_ERR_NO_बफर_SPACE			-9
#परिभाषय SSH_ERR_INVALID_तर्कः		-10
#परिभाषय SSH_ERR_कुञ्चिका_द्वयङ्काः_MISMATCH		-11
#परिभाषय SSH_ERR_EC_वक्रम्_INVALID		-12
#परिभाषय SSH_ERR_कुञ्चिका_TYPE_MISMATCH		-13
#परिभाषय SSH_ERR_कुञ्चिका_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#परिभाषय SSH_ERR_EC_वक्रम्_MISMATCH		-15
#परिभाषय SSH_ERR_EXPECTED_CERT			-16
#परिभाषय SSH_ERR_कुञ्चिका_LACKS_CERTBLOB		-17
#परिभाषय SSH_ERR_कुञ्चिका_CERT_UNKNOWN_TYPE		-18
#परिभाषय SSH_ERR_कुञ्चिका_CERT_INVALID_SIGN_कुञ्चिका	-19
#परिभाषय SSH_ERR_कुञ्चिका_INVALID_EC_मानम्		-20
#परिभाषय SSH_ERR_SIGNATURE_INVALID		-21
#परिभाषय SSH_ERR_LIBCRYPTO_ERROR			-22
#परिभाषय SSH_ERR_UNEXPECTED_TRAILING_दत्त	-23
#परिभाषय SSH_ERR_SYSTEM_ERROR			-24
#परिभाषय SSH_ERR_कुञ्चिका_CERT_INVALID		-25
#परिभाषय SSH_ERR_AGENT_COMMUNICATION		-26
#परिभाषय SSH_ERR_AGENT_FAILURE			-27
#परिभाषय SSH_ERR_DH_GEX_बहिर्गमनम्_सम्बन्धि_RANGE		-28
#परिभाषय SSH_ERR_DISCONNECTED			-29
#परिभाषय SSH_ERR_MAC_INVALID			-30
#परिभाषय SSH_ERR_NO_CIPHER_ALG_मेलनम्		-31
#परिभाषय SSH_ERR_NO_MAC_ALG_मेलनम्		-32
#परिभाषय SSH_ERR_NO_COMPRESS_ALG_मेलनम्		-33
#परिभाषय SSH_ERR_NO_KEX_ALG_मेलनम्		-34
#परिभाषय SSH_ERR_NO_HOSTKEY_ALG_मेलनम्		-35
#परिभाषय SSH_ERR_NO_HOSTKEY_LOADED		-36
#परिभाषय SSH_ERR_PROTOCOL_MISMATCH		-37
#परिभाषय SSH_ERR_NO_PROTOCOL_संस्करणम्		-38
#परिभाषय SSH_ERR_NEED_REKEY			-39
#परिभाषय SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#परिभाषय SSH_ERR_FILE_परिवर्तितम्			-41
#परिभाषय SSH_ERR_कुञ्चिका_UNKNOWN_CIPHER		-42
#परिभाषय SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE		-43
#परिभाषय SSH_ERR_कुञ्चिका_BAD_PERMISSIONS		-44
#परिभाषय SSH_ERR_कुञ्चिका_CERT_MISMATCH		-45
#परिभाषय SSH_ERR_कुञ्चिका_NOT_प्राप्तम्			-46
#परिभाषय SSH_ERR_AGENT_NOT_PRESENT		-47
#परिभाषय SSH_ERR_AGENT_NO_IDENTITIES		-48
#परिभाषय SSH_ERR_बफर_READ_ONLY		-49
#परिभाषय SSH_ERR_KRL_BAD_MAGIC			-50
#परिभाषय SSH_ERR_कुञ्चिका_REVOKED			-51
#परिभाषय SSH_ERR_CONN_CLOSED			-52
#परिभाषय SSH_ERR_CONN_TIMEOUT			-53
#परिभाषय SSH_ERR_CONN_CORRUPT			-54
#परिभाषय SSH_ERR_PROTOCOL_ERROR			-55
#परिभाषय SSH_ERR_कुञ्चिका_दीर्घता			-56
#परिभाषय SSH_ERR_सङ्ख्या_TOO_LARGE		-57
#परिभाषय SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#परिभाषय SSH_ERR_FEATURE_UNSUPPORTED		-59
#परिभाषय SSH_ERR_DEVICE_NOT_प्राप्तम्		-60
#परिभाषय SSH_ERR_CRYPTO_ERROR			-61
#परिभाषय SSH_ERR_आन्तरिकम्_CRYPTO_ERROR		-62
#परिभाषय SSH_ERR_कुञ्चिका_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
ध्रुव वर्ण *ssh_err(पूर्णाङ्क n);
/* Return most recent error from libcrypto. */
ध्रुव वर्ण *ssherr_libcrypto(शून्य);

#यदि_अन्तः /* _SSHERR_H */
