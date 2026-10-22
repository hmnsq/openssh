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

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ଅଚଳ ଅକ୍ଷର *
ssh_err(ପୂର୍ଣ୍ଣସଂଖ୍ୟା n)
{
	ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;

	ବାଛ (n) {
	ସ୍ଥିତି SSH_ERR_SUCCESS:
		ଫେରନ୍ତୁ "success";
	ସ୍ଥିତି SSH_ERR_INTERNAL_ERROR:
		ଫେରନ୍ତୁ "unexpected internal error";
	ସ୍ଥିତି SSH_ERR_ALLOC_FAIL:
		ଫେରନ୍ତୁ "memory allocation failed";
	ସ୍ଥିତି SSH_ERR_MESSAGE_INCOMPLETE:
		ଫେରନ୍ତୁ "incomplete message";
	ସ୍ଥିତି SSH_ERR_INVALID_FORMAT:
		ଫେରନ୍ତୁ "invalid format";
	ସ୍ଥିତି SSH_ERR_BIGNUM_IS_NEGATIVE:
		ଫେରନ୍ତୁ "bignum is negative";
	ସ୍ଥିତି SSH_ERR_STRING_TOO_LARGE:
		ଫେରନ୍ତୁ "string is too large";
	ସ୍ଥିତି SSH_ERR_BIGNUM_TOO_LARGE:
		ଫେରନ୍ତୁ "bignum is too large";
	ସ୍ଥିତି SSH_ERR_ECPOINT_TOO_LARGE:
		ଫେରନ୍ତୁ "elliptic curve point is too large";
	ସ୍ଥିତି SSH_ERR_NO_BUFFER_SPACE:
		ଫେରନ୍ତୁ "insufficient buffer space";
	ସ୍ଥିତି SSH_ERR_INVALID_ARGUMENT:
		ଫେରନ୍ତୁ "invalid argument";
	ସ୍ଥିତି SSH_ERR_ଚାବି_BITS_MISMATCH:
		ଫେରନ୍ତୁ "key bits do not match";
	ସ୍ଥିତି SSH_ERR_EC_CURVE_INVALID:
		ଫେରନ୍ତୁ "invalid elliptic curve";
	ସ୍ଥିତି SSH_ERR_ଚାବି_TYPE_MISMATCH:
		ଫେରନ୍ତୁ "key type does not match";
	ସ୍ଥିତି SSH_ERR_ଚାବି_TYPE_UNKNOWN:
		ଫେରନ୍ତୁ "unknown or unsupported key type";
	ସ୍ଥିତି SSH_ERR_EC_CURVE_MISMATCH:
		ଫେରନ୍ତୁ "elliptic curve does not match";
	ସ୍ଥିତି SSH_ERR_EXPECTED_CERT:
		ଫେରନ୍ତୁ "plain key provided where certificate required";
	ସ୍ଥିତି SSH_ERR_ଚାବି_LACKS_CERTBLOB:
		ଫେରନ୍ତୁ "key lacks certificate data";
	ସ୍ଥିତି SSH_ERR_ଚାବି_CERT_UNKNOWN_TYPE:
		ଫେରନ୍ତୁ "unknown/unsupported certificate type";
	ସ୍ଥିତି SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି:
		ଫେରନ୍ତୁ "invalid certificate signing key";
	ସ୍ଥିତି SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ:
		ଫେରନ୍ତୁ "invalid elliptic curve value";
	ସ୍ଥିତି SSH_ERR_SIGNATURE_INVALID:
		ଫେରନ୍ତୁ "incorrect signature";
	ସ୍ଥିତି SSH_ERR_LIBCRYPTO_ERROR:
		ସନ୍ଦେଶ = ssherr_libcrypto();
		ଫେରନ୍ତୁ ସନ୍ଦେଶ != ଖାଲି ? ସନ୍ଦେଶ : "error in libcrypto";
	ସ୍ଥିତି SSH_ERR_INTERNAL_CRYPTO_ERROR:
		ଫେରନ୍ତୁ "cryptographic operation failed";
	ସ୍ଥିତି SSH_ERR_UNEXPECTED_TRAILING_DATA:
		ଫେରନ୍ତୁ "unexpected bytes remain after decoding";
	ସ୍ଥିତି SSH_ERR_SYSTEM_ERROR:
		ଫେରନ୍ତୁ strerror(errno);
	ସ୍ଥିତି SSH_ERR_ଚାବି_CERT_INVALID:
		ଫେରନ୍ତୁ "invalid certificate";
	ସ୍ଥିତି SSH_ERR_AGENT_COMMUNICATION:
		ଫେରନ୍ତୁ "communication with agent failed";
	ସ୍ଥିତି SSH_ERR_AGENT_FAILURE:
		ଫେରନ୍ତୁ "agent refused operation";
	ସ୍ଥିତି SSH_ERR_DH_GEX_OUT_OF_RANGE:
		ଫେରନ୍ତୁ "DH GEX group out of range";
	ସ୍ଥିତି SSH_ERR_DISCONNECTED:
		ଫେରନ୍ତୁ "disconnected";
	ସ୍ଥିତି SSH_ERR_MAC_INVALID:
		ଫେରନ୍ତୁ "message authentication code incorrect";
	ସ୍ଥିତି SSH_ERR_NO_CIPHER_ALG_MATCH:
		ଫେରନ୍ତୁ "no matching cipher found";
	ସ୍ଥିତି SSH_ERR_NO_MAC_ALG_MATCH:
		ଫେରନ୍ତୁ "no matching MAC found";
	ସ୍ଥିତି SSH_ERR_NO_COMPRESS_ALG_MATCH:
		ଫେରନ୍ତୁ "no matching compression method found";
	ସ୍ଥିତି SSH_ERR_NO_KEX_ALG_MATCH:
		ଫେରନ୍ତୁ "no matching key exchange method found";
	ସ୍ଥିତି SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		ଫେରନ୍ତୁ "no matching host key type found";
	ସ୍ଥିତି SSH_ERR_PROTOCOL_MISMATCH:
		ଫେରନ୍ତୁ "protocol version mismatch";
	ସ୍ଥିତି SSH_ERR_NO_PROTOCOL_VERSION:
		ଫେରନ୍ତୁ "could not read protocol version";
	ସ୍ଥିତି SSH_ERR_NO_HOSTKEY_LOADED:
		ଫେରନ୍ତୁ "could not load host key";
	ସ୍ଥିତି SSH_ERR_NEED_REKEY:
		ଫେରନ୍ତୁ "rekeying not supported by peer";
	ସ୍ଥିତି SSH_ERR_PASSPHRASE_TOO_SHORT:
		ଫେରନ୍ତୁ "passphrase is too short (minimum five characters)";
	ସ୍ଥିତି SSH_ERR_FILE_CHANGED:
		ଫେରନ୍ତୁ "file changed while reading";
	ସ୍ଥିତି SSH_ERR_ଚାବି_UNKNOWN_CIPHER:
		ଫେରନ୍ତୁ "key encrypted using unsupported cipher";
	ସ୍ଥିତି SSH_ERR_ଚାବି_WRONG_PASSPHRASE:
		ଫେରନ୍ତୁ "incorrect passphrase supplied to decrypt private key";
	ସ୍ଥିତି SSH_ERR_ଚାବି_BAD_PERMISSIONS:
		ଫେରନ୍ତୁ "bad permissions";
	ସ୍ଥିତି SSH_ERR_ଚାବି_CERT_MISMATCH:
		ଫେରନ୍ତୁ "certificate does not match key";
	ସ୍ଥିତି SSH_ERR_ଚାବି_NOT_FOUND:
		ଫେରନ୍ତୁ "key not found";
	ସ୍ଥିତି SSH_ERR_AGENT_NOT_PRESENT:
		ଫେରନ୍ତୁ "agent not present";
	ସ୍ଥିତି SSH_ERR_AGENT_NO_IDENTITIES:
		ଫେରନ୍ତୁ "agent contains no identities";
	ସ୍ଥିତି SSH_ERR_BUFFER_READ_ONLY:
		ଫେରନ୍ତୁ "internal error: buffer is read-only";
	ସ୍ଥିତି SSH_ERR_KRL_BAD_MAGIC:
		ଫେରନ୍ତୁ "KRL file has invalid magic number";
	ସ୍ଥିତି SSH_ERR_ଚାବି_REVOKED:
		ଫେରନ୍ତୁ "Key is revoked";
	ସ୍ଥିତି SSH_ERR_CONN_CLOSED:
		ଫେରନ୍ତୁ "Connection closed";
	ସ୍ଥିତି SSH_ERR_CONN_TIMEOUT:
		ଫେରନ୍ତୁ "Connection timed out";
	ସ୍ଥିତି SSH_ERR_CONN_CORRUPT:
		ଫେରନ୍ତୁ "Connection corrupted";
	ସ୍ଥିତି SSH_ERR_PROTOCOL_ERROR:
		ଫେରନ୍ତୁ "Protocol error";
	ସ୍ଥିତି SSH_ERR_ଚାବି_LENGTH:
		ଫେରନ୍ତୁ "Invalid key length";
	ସ୍ଥିତି SSH_ERR_ସଂଖ୍ୟା_TOO_LARGE:
		ଫେରନ୍ତୁ "number is too large";
	ସ୍ଥିତି SSH_ERR_ଚାବି_ALG_UNSUPPORTED:
		ଫେରନ୍ତୁ "key algorithm not supported";
	ସ୍ଥିତି SSH_ERR_SIGN_ALG_UNSUPPORTED:
		ଫେରନ୍ତୁ "signature algorithm not supported";
	ସ୍ଥିତି SSH_ERR_FEATURE_UNSUPPORTED:
		ଫେରନ୍ତୁ "requested feature not supported";
	ସ୍ଥିତି SSH_ERR_DEVICE_NOT_FOUND:
		ଫେରନ୍ତୁ "device not found";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ "unknown error";
	}
}
