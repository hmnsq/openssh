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

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ "ssherr.h"

மாறிலி எழுத்து *
ssh_err(முழு n)
{
	மாறிலி எழுத்து *செய்தி = வெற்று;

	தேர்வு (n) {
	நிலை SSH_ERR_SUCCESS:
		திரும்பு "success";
	நிலை SSH_ERR_INTERNAL_ERROR:
		திரும்பு "unexpected internal error";
	நிலை SSH_ERR_ALLOC_FAIL:
		திரும்பு "memory allocation failed";
	நிலை SSH_ERR_MESSAGE_INCOMPLETE:
		திரும்பு "incomplete message";
	நிலை SSH_ERR_INVALID_FORMAT:
		திரும்பு "invalid format";
	நிலை SSH_ERR_BIGNUM_IS_NEGATIVE:
		திரும்பு "bignum is negative";
	நிலை SSH_ERR_STRING_TOO_LARGE:
		திரும்பு "string is too large";
	நிலை SSH_ERR_BIGNUM_TOO_LARGE:
		திரும்பு "bignum is too large";
	நிலை SSH_ERR_ECPOINT_TOO_LARGE:
		திரும்பு "elliptic curve point is too large";
	நிலை SSH_ERR_NO_BUFFER_SPACE:
		திரும்பு "insufficient buffer space";
	நிலை SSH_ERR_INVALID_ARGUMENT:
		திரும்பு "invalid argument";
	நிலை SSH_ERR_சாவி_BITS_MISMATCH:
		திரும்பு "key bits do not match";
	நிலை SSH_ERR_EC_CURVE_INVALID:
		திரும்பு "invalid elliptic curve";
	நிலை SSH_ERR_சாவி_TYPE_MISMATCH:
		திரும்பு "key type does not match";
	நிலை SSH_ERR_சாவி_TYPE_UNKNOWN:
		திரும்பு "unknown or unsupported key type";
	நிலை SSH_ERR_EC_CURVE_MISMATCH:
		திரும்பு "elliptic curve does not match";
	நிலை SSH_ERR_EXPECTED_CERT:
		திரும்பு "plain key provided where certificate required";
	நிலை SSH_ERR_சாவி_LACKS_CERTBLOB:
		திரும்பு "key lacks certificate data";
	நிலை SSH_ERR_சாவி_CERT_UNKNOWN_TYPE:
		திரும்பு "unknown/unsupported certificate type";
	நிலை SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி:
		திரும்பு "invalid certificate signing key";
	நிலை SSH_ERR_சாவி_INVALID_EC_மதிப்பு:
		திரும்பு "invalid elliptic curve value";
	நிலை SSH_ERR_SIGNATURE_INVALID:
		திரும்பு "incorrect signature";
	நிலை SSH_ERR_LIBCRYPTO_ERROR:
		செய்தி = ssherr_libcrypto();
		திரும்பு செய்தி != வெற்று ? செய்தி : "error in libcrypto";
	நிலை SSH_ERR_INTERNAL_CRYPTO_ERROR:
		திரும்பு "cryptographic operation failed";
	நிலை SSH_ERR_UNEXPECTED_TRAILING_DATA:
		திரும்பு "unexpected bytes remain after decoding";
	நிலை SSH_ERR_SYSTEM_ERROR:
		திரும்பு strerror(errno);
	நிலை SSH_ERR_சாவி_CERT_INVALID:
		திரும்பு "invalid certificate";
	நிலை SSH_ERR_AGENT_COMMUNICATION:
		திரும்பு "communication with agent failed";
	நிலை SSH_ERR_AGENT_FAILURE:
		திரும்பு "agent refused operation";
	நிலை SSH_ERR_DH_GEX_OUT_OF_RANGE:
		திரும்பு "DH GEX group out of range";
	நிலை SSH_ERR_DISCONNECTED:
		திரும்பு "disconnected";
	நிலை SSH_ERR_MAC_INVALID:
		திரும்பு "message authentication code incorrect";
	நிலை SSH_ERR_NO_CIPHER_ALG_MATCH:
		திரும்பு "no matching cipher found";
	நிலை SSH_ERR_NO_MAC_ALG_MATCH:
		திரும்பு "no matching MAC found";
	நிலை SSH_ERR_NO_COMPRESS_ALG_MATCH:
		திரும்பு "no matching compression method found";
	நிலை SSH_ERR_NO_KEX_ALG_MATCH:
		திரும்பு "no matching key exchange method found";
	நிலை SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		திரும்பு "no matching host key type found";
	நிலை SSH_ERR_PROTOCOL_MISMATCH:
		திரும்பு "protocol version mismatch";
	நிலை SSH_ERR_NO_PROTOCOL_VERSION:
		திரும்பு "could not read protocol version";
	நிலை SSH_ERR_NO_HOSTKEY_LOADED:
		திரும்பு "could not load host key";
	நிலை SSH_ERR_NEED_REKEY:
		திரும்பு "rekeying not supported by peer";
	நிலை SSH_ERR_PASSPHRASE_TOO_SHORT:
		திரும்பு "passphrase is too short (minimum five characters)";
	நிலை SSH_ERR_FILE_CHANGED:
		திரும்பு "file changed while reading";
	நிலை SSH_ERR_சாவி_UNKNOWN_CIPHER:
		திரும்பு "key encrypted using unsupported cipher";
	நிலை SSH_ERR_சாவி_WRONG_PASSPHRASE:
		திரும்பு "incorrect passphrase supplied to decrypt private key";
	நிலை SSH_ERR_சாவி_BAD_PERMISSIONS:
		திரும்பு "bad permissions";
	நிலை SSH_ERR_சாவி_CERT_MISMATCH:
		திரும்பு "certificate does not match key";
	நிலை SSH_ERR_சாவி_NOT_FOUND:
		திரும்பு "key not found";
	நிலை SSH_ERR_AGENT_NOT_PRESENT:
		திரும்பு "agent not present";
	நிலை SSH_ERR_AGENT_NO_IDENTITIES:
		திரும்பு "agent contains no identities";
	நிலை SSH_ERR_BUFFER_READ_ONLY:
		திரும்பு "internal error: buffer is read-only";
	நிலை SSH_ERR_KRL_BAD_MAGIC:
		திரும்பு "KRL file has invalid magic number";
	நிலை SSH_ERR_சாவி_REVOKED:
		திரும்பு "Key is revoked";
	நிலை SSH_ERR_CONN_CLOSED:
		திரும்பு "Connection closed";
	நிலை SSH_ERR_CONN_TIMEOUT:
		திரும்பு "Connection timed out";
	நிலை SSH_ERR_CONN_CORRUPT:
		திரும்பு "Connection corrupted";
	நிலை SSH_ERR_PROTOCOL_ERROR:
		திரும்பு "Protocol error";
	நிலை SSH_ERR_சாவி_LENGTH:
		திரும்பு "Invalid key length";
	நிலை SSH_ERR_எண்_TOO_LARGE:
		திரும்பு "number is too large";
	நிலை SSH_ERR_சாவி_ALG_UNSUPPORTED:
		திரும்பு "key algorithm not supported";
	நிலை SSH_ERR_SIGN_ALG_UNSUPPORTED:
		திரும்பு "signature algorithm not supported";
	நிலை SSH_ERR_FEATURE_UNSUPPORTED:
		திரும்பு "requested feature not supported";
	நிலை SSH_ERR_DEVICE_NOT_FOUND:
		திரும்பு "device not found";
	இயல்பு:
		திரும்பு "unknown error";
	}
}
