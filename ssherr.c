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

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ "ssherr.h"

స్థిరరాశి అక్షరం *
ssh_err(పూర్ణాంకం n)
{
	స్థిరరాశి అక్షరం *సందేశం = ఖాళీ;

	ఎంపిక (n) {
	స్థితి SSH_ERR_SUCCESS:
		తిరిగి "success";
	స్థితి SSH_ERR_అంతర్గత_ERROR:
		తిరిగి "unexpected internal error";
	స్థితి SSH_ERR_ALLOC_FAIL:
		తిరిగి "memory allocation failed";
	స్థితి SSH_ERR_సందేశం_INCOMPLETE:
		తిరిగి "incomplete message";
	స్థితి SSH_ERR_INVALID_FORMAT:
		తిరిగి "invalid format";
	స్థితి SSH_ERR_BIGNUM_IS_NEGATIVE:
		తిరిగి "bignum is negative";
	స్థితి SSH_ERR_STRING_TOO_LARGE:
		తిరిగి "string is too large";
	స్థితి SSH_ERR_BIGNUM_TOO_LARGE:
		తిరిగి "bignum is too large";
	స్థితి SSH_ERR_ECPOINT_TOO_LARGE:
		తిరిగి "elliptic curve point is too large";
	స్థితి SSH_ERR_NO_బఫరు_SPACE:
		తిరిగి "insufficient buffer space";
	స్థితి SSH_ERR_INVALID_వాదం:
		తిరిగి "invalid argument";
	స్థితి SSH_ERR_కీలకం_బిట్లు_MISMATCH:
		తిరిగి "key bits do not match";
	స్థితి SSH_ERR_EC_వక్రం_INVALID:
		తిరిగి "invalid elliptic curve";
	స్థితి SSH_ERR_కీలకం_TYPE_MISMATCH:
		తిరిగి "key type does not match";
	స్థితి SSH_ERR_కీలకం_TYPE_UNKNOWN:
		తిరిగి "unknown or unsupported key type";
	స్థితి SSH_ERR_EC_వక్రం_MISMATCH:
		తిరిగి "elliptic curve does not match";
	స్థితి SSH_ERR_EXPECTED_CERT:
		తిరిగి "plain key provided where certificate required";
	స్థితి SSH_ERR_కీలకం_LACKS_CERTBLOB:
		తిరిగి "key lacks certificate data";
	స్థితి SSH_ERR_కీలకం_CERT_UNKNOWN_TYPE:
		తిరిగి "unknown/unsupported certificate type";
	స్థితి SSH_ERR_కీలకం_CERT_INVALID_SIGN_కీలకం:
		తిరిగి "invalid certificate signing key";
	స్థితి SSH_ERR_కీలకం_INVALID_EC_విలువ:
		తిరిగి "invalid elliptic curve value";
	స్థితి SSH_ERR_SIGNATURE_INVALID:
		తిరిగి "incorrect signature";
	స్థితి SSH_ERR_LIBCRYPTO_ERROR:
		సందేశం = ssherr_libcrypto();
		తిరిగి సందేశం != ఖాళీ ? సందేశం : "error in libcrypto";
	స్థితి SSH_ERR_అంతర్గత_CRYPTO_ERROR:
		తిరిగి "cryptographic operation failed";
	స్థితి SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం:
		తిరిగి "unexpected bytes remain after decoding";
	స్థితి SSH_ERR_SYSTEM_ERROR:
		తిరిగి strerror(errno);
	స్థితి SSH_ERR_కీలకం_CERT_INVALID:
		తిరిగి "invalid certificate";
	స్థితి SSH_ERR_AGENT_COMMUNICATION:
		తిరిగి "communication with agent failed";
	స్థితి SSH_ERR_AGENT_FAILURE:
		తిరిగి "agent refused operation";
	స్థితి SSH_ERR_DH_GEX_బహిర్గతం_యొక్క_RANGE:
		తిరిగి "DH GEX group out of range";
	స్థితి SSH_ERR_DISCONNECTED:
		తిరిగి "disconnected";
	స్థితి SSH_ERR_MAC_INVALID:
		తిరిగి "message authentication code incorrect";
	స్థితి SSH_ERR_NO_CIPHER_ALG_సరిపోలిక:
		తిరిగి "no matching cipher found";
	స్థితి SSH_ERR_NO_MAC_ALG_సరిపోలిక:
		తిరిగి "no matching MAC found";
	స్థితి SSH_ERR_NO_COMPRESS_ALG_సరిపోలిక:
		తిరిగి "no matching compression method found";
	స్థితి SSH_ERR_NO_KEX_ALG_సరిపోలిక:
		తిరిగి "no matching key exchange method found";
	స్థితి SSH_ERR_NO_HOSTKEY_ALG_సరిపోలిక:
		తిరిగి "no matching host key type found";
	స్థితి SSH_ERR_PROTOCOL_MISMATCH:
		తిరిగి "protocol version mismatch";
	స్థితి SSH_ERR_NO_PROTOCOL_సంస్కరణ:
		తిరిగి "could not read protocol version";
	స్థితి SSH_ERR_NO_HOSTKEY_LOADED:
		తిరిగి "could not load host key";
	స్థితి SSH_ERR_NEED_REKEY:
		తిరిగి "rekeying not supported by peer";
	స్థితి SSH_ERR_PASSPHRASE_TOO_SHORT:
		తిరిగి "passphrase is too short (minimum five characters)";
	స్థితి SSH_ERR_FILE_మారింది:
		తిరిగి "file changed while reading";
	స్థితి SSH_ERR_కీలకం_UNKNOWN_CIPHER:
		తిరిగి "key encrypted using unsupported cipher";
	స్థితి SSH_ERR_కీలకం_WRONG_PASSPHRASE:
		తిరిగి "incorrect passphrase supplied to decrypt private key";
	స్థితి SSH_ERR_కీలకం_BAD_PERMISSIONS:
		తిరిగి "bad permissions";
	స్థితి SSH_ERR_కీలకం_CERT_MISMATCH:
		తిరిగి "certificate does not match key";
	స్థితి SSH_ERR_కీలకం_NOT_దొరికింది:
		తిరిగి "key not found";
	స్థితి SSH_ERR_AGENT_NOT_PRESENT:
		తిరిగి "agent not present";
	స్థితి SSH_ERR_AGENT_NO_IDENTITIES:
		తిరిగి "agent contains no identities";
	స్థితి SSH_ERR_బఫరు_READ_ONLY:
		తిరిగి "internal error: buffer is read-only";
	స్థితి SSH_ERR_KRL_BAD_MAGIC:
		తిరిగి "KRL file has invalid magic number";
	స్థితి SSH_ERR_కీలకం_REVOKED:
		తిరిగి "Key is revoked";
	స్థితి SSH_ERR_CONN_CLOSED:
		తిరిగి "Connection closed";
	స్థితి SSH_ERR_CONN_TIMEOUT:
		తిరిగి "Connection timed out";
	స్థితి SSH_ERR_CONN_CORRUPT:
		తిరిగి "Connection corrupted";
	స్థితి SSH_ERR_PROTOCOL_ERROR:
		తిరిగి "Protocol error";
	స్థితి SSH_ERR_కీలకం_నిడివి:
		తిరిగి "Invalid key length";
	స్థితి SSH_ERR_సంఖ్య_TOO_LARGE:
		తిరిగి "number is too large";
	స్థితి SSH_ERR_కీలకం_ALG_UNSUPPORTED:
		తిరిగి "key algorithm not supported";
	స్థితి SSH_ERR_SIGN_ALG_UNSUPPORTED:
		తిరిగి "signature algorithm not supported";
	స్థితి SSH_ERR_FEATURE_UNSUPPORTED:
		తిరిగి "requested feature not supported";
	స్థితి SSH_ERR_DEVICE_NOT_దొరికింది:
		తిరిగి "device not found";
	అప్రమేయ:
		తిరిగి "unknown error";
	}
}
