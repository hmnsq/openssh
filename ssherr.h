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

#నిర్వచితం_కాకపోతే _SSHERR_H
#నిర్వచించు _SSHERR_H

/* XXX are these too granular? not granular enough? I can't decide - djm */

/* Error codes */
#నిర్వచించు SSH_ERR_SUCCESS				0
#నిర్వచించు SSH_ERR_అంతర్గత_ERROR			-1
#నిర్వచించు SSH_ERR_ALLOC_FAIL			-2
#నిర్వచించు SSH_ERR_సందేశం_INCOMPLETE		-3
#నిర్వచించు SSH_ERR_INVALID_FORMAT			-4
#నిర్వచించు SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#నిర్వచించు SSH_ERR_STRING_TOO_LARGE		-6
#నిర్వచించు SSH_ERR_BIGNUM_TOO_LARGE		-7
#నిర్వచించు SSH_ERR_ECPOINT_TOO_LARGE		-8
#నిర్వచించు SSH_ERR_NO_బఫరు_SPACE			-9
#నిర్వచించు SSH_ERR_INVALID_వాదం		-10
#నిర్వచించు SSH_ERR_కీలకం_బిట్లు_MISMATCH		-11
#నిర్వచించు SSH_ERR_EC_వక్రం_INVALID		-12
#నిర్వచించు SSH_ERR_కీలకం_TYPE_MISMATCH		-13
#నిర్వచించు SSH_ERR_కీలకం_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#నిర్వచించు SSH_ERR_EC_వక్రం_MISMATCH		-15
#నిర్వచించు SSH_ERR_EXPECTED_CERT			-16
#నిర్వచించు SSH_ERR_కీలకం_LACKS_CERTBLOB		-17
#నిర్వచించు SSH_ERR_కీలకం_CERT_UNKNOWN_TYPE		-18
#నిర్వచించు SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం	-19
#నిర్వచించు SSH_ERR_కీలకం_INVALID_EC_విలువ		-20
#నిర్వచించు SSH_ERR_SIGNATURE_INVALID		-21
#నిర్వచించు SSH_ERR_LIBCRYPTO_ERROR			-22
#నిర్వచించు SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం	-23
#నిర్వచించు SSH_ERR_SYSTEM_ERROR			-24
#నిర్వచించు SSH_ERR_కీలకం_CERT_INVALID		-25
#నిర్వచించు SSH_ERR_AGENT_COMMUNICATION		-26
#నిర్వచించు SSH_ERR_AGENT_FAILURE			-27
#నిర్వచించు SSH_ERR_DH_GEX_బహిర్గతం_యొక్క_RANGE		-28
#నిర్వచించు SSH_ERR_DISCONNECTED			-29
#నిర్వచించు SSH_ERR_MAC_INVALID			-30
#నిర్వచించు SSH_ERR_NO_CIPHER_ALG_సరిపోలిక		-31
#నిర్వచించు SSH_ERR_NO_MAC_ALG_సరిపోలిక		-32
#నిర్వచించు SSH_ERR_NO_COMPRESS_ALG_సరిపోలిక		-33
#నిర్వచించు SSH_ERR_NO_KEX_ALG_సరిపోలిక		-34
#నిర్వచించు SSH_ERR_NO_HOSTKEY_ALG_సరిపోలిక		-35
#నిర్వచించు SSH_ERR_NO_HOSTKEY_LOADED		-36
#నిర్వచించు SSH_ERR_PROTOCOL_MISMATCH		-37
#నిర్వచించు SSH_ERR_NO_PROTOCOL_సంస్కరణ		-38
#నిర్వచించు SSH_ERR_NEED_REKEY			-39
#నిర్వచించు SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#నిర్వచించు SSH_ERR_FILE_మారింది			-41
#నిర్వచించు SSH_ERR_కీలకం_UNKNOWN_CIPHER		-42
#నిర్వచించు SSH_ERR_కీలకం_WRONG_PASSPHRASE		-43
#నిర్వచించు SSH_ERR_కీలకం_BAD_PERMISSIONS		-44
#నిర్వచించు SSH_ERR_కీలకం_CERT_MISMATCH		-45
#నిర్వచించు SSH_ERR_కీలకం_NOT_దొరికింది			-46
#నిర్వచించు SSH_ERR_AGENT_NOT_PRESENT		-47
#నిర్వచించు SSH_ERR_AGENT_NO_IDENTITIES		-48
#నిర్వచించు SSH_ERR_బఫరు_READ_ONLY		-49
#నిర్వచించు SSH_ERR_KRL_BAD_MAGIC			-50
#నిర్వచించు SSH_ERR_కీలకం_REVOKED			-51
#నిర్వచించు SSH_ERR_CONN_CLOSED			-52
#నిర్వచించు SSH_ERR_CONN_TIMEOUT			-53
#నిర్వచించు SSH_ERR_CONN_CORRUPT			-54
#నిర్వచించు SSH_ERR_PROTOCOL_ERROR			-55
#నిర్వచించు SSH_ERR_కీలకం_నిడివి			-56
#నిర్వచించు SSH_ERR_సంఖ్య_TOO_LARGE		-57
#నిర్వచించు SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#నిర్వచించు SSH_ERR_FEATURE_UNSUPPORTED		-59
#నిర్వచించు SSH_ERR_DEVICE_NOT_దొరికింది		-60
#నిర్వచించు SSH_ERR_CRYPTO_ERROR			-61
#నిర్వచించు SSH_ERR_అంతర్గత_CRYPTO_ERROR		-62
#నిర్వచించు SSH_ERR_కీలకం_ALG_UNSUPPORTED		-63

/* Translate a numeric error code to a human-readable error string */
స్థిరరాశి అక్షరం *ssh_err(పూర్ణాంకం n);
/* Return most recent error from libcrypto. */
స్థిరరాశి అక్షరం *ssherr_libcrypto(శూన్య);

#అయితే_ముగింపు /* _SSHERR_H */
