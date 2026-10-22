/* $OpenBSD: dns.c,v 1.48 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2003 Wesley Griffin. All rights reserved.
 * Copyright (c) 2003 Jakob Schlyter. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "dns.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ errset_ಪಠ್ಯ[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
dns_ಫಲಿತಾಂಶ_totext(ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ res)
{
	ಆಯ್ಕೆ (res) {
	ಸ್ಥಿತಿ ERRSET_SUCCESS:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_SUCCESS];
	ಸ್ಥಿತಿ ERRSET_NOMEMORY:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_NOMEMORY];
	ಸ್ಥಿತಿ ERRSET_FAIL:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_FAIL];
	ಸ್ಥಿತಿ ERRSET_INVAL:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_INVAL];
	ಸ್ಥಿತಿ ERRSET_NONAME:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_NONAME];
	ಸ್ಥಿತಿ ERRSET_NODATA:
		ಹಿಂತಿರುಗಿ errset_ಪಠ್ಯ[ERRSET_NODATA];
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
dns_read_ಕೀಲಿ(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, ಗಾತ್ರ_t *digest_len, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ಪೂರ್ಣಾಂಕ fp_alg = -1;

	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		*algorithm = SSHFP_ಕೀಲಿ_RSA;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		*algorithm = SSHFP_ಕೀಲಿ_ECDSA;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		*algorithm = SSHFP_ಕೀಲಿ_ED25519;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		*algorithm = SSHFP_ಕೀಲಿ_RESERVED; /* 0 */
	}

	ಆಯ್ಕೆ (*digest_type) {
	ಸ್ಥಿತಿ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ಆದರೆ (*algorithm && *digest_type) {
		ಆದರೆ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		*digest = ಖಾಲಿ;
		*digest_len = 0;
	}

	ಹಿಂತಿರುಗಿ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, ಗಾತ್ರ_t *digest_len, u_char *rdata, ಪೂರ್ಣಾಂಕ rdata_len)
{
	ಪೂರ್ಣಾಂಕ success = 0;

	*algorithm = SSHFP_ಕೀಲಿ_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ಆದರೆ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ಆದರೆ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			ಸ್ಮರಣೆ_ನಕಲು(*digest, rdata + 2, *digest_len);
		} ಇಲ್ಲದಿದ್ದರೆ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	ಹಿಂತಿರುಗಿ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_numeric_hostname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname)
{
	ರಚನೆ addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ಆದರೆ (hostname == ಖಾಲಿ) {
		error("is_numeric_hostname called with NULL hostname");
		ಹಿಂತಿರುಗಿ -1;
	}

	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ಆದರೆ (getaddrinfo(hostname, ಖಾಲಿ, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
ಪೂರ್ಣಾಂಕ
verify_host_ಕೀಲಿ_dns(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ರಚನೆ sockaddr *ವಿಳಾಸ,
    ರಚನೆ sshkey *hostkey, ಪೂರ್ಣಾಂಕ *flags)
{
	u_int counter;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ;
	ರಚನೆ rrsetinfo *fingerprints = ಖಾಲಿ;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	ಗಾತ್ರ_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	ಗಾತ್ರ_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ಆದರೆ (hostkey == ಖಾಲಿ)
		fatal("No key to look up!");

	ಆದರೆ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ಹಿಂತಿರುಗಿ -1;
	}

	ಫಲಿತಾಂಶ = getrrsetbyname(hostname, DNS_RDATACLASS_ಒಳ,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ಆದರೆ (ಫಲಿತಾಂಶ) {
		verbose("DNS lookup error: %s", dns_ಫಲಿತಾಂಶ_totext(ಫಲಿತಾಂಶ));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ಆದರೆ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_ಸಿಕ್ಕಿತು;

	ಗಾಗಿ (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ಆದರೆ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_ದತ್ತಾಂಶ,
		    fingerprints->rri_rdatas[counter].rdi_ಉದ್ದಳತೆ)) {
			verbose("Error parsing fingerprint from DNS.");
			ಮುಂದುವರಿ;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ಆದರೆ (!dns_read_ಕೀಲಿ(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			ಬಿಡುಗಡೆ(dnskey_digest);
			freerrset(fingerprints);
			ಹಿಂತಿರುಗಿ -1;
		}

		/* Check if the current key is the same as the given key */
		ಆದರೆ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ಆದರೆ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_ಹೊಂದಿಕೆ;
			} ಇಲ್ಲದಿದ್ದರೆ {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		ಬಿಡುಗಡೆ(dnskey_digest);
		ಬಿಡುಗಡೆ(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	ಆದರೆ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_ಹೊಂದಿಕೆ;

	ಆದರೆ (*flags & DNS_VERIFY_ಸಿಕ್ಕಿತು)
		ಆದರೆ (*flags & DNS_VERIFY_ಹೊಂದಿಕೆ)
			debug("matching host key fingerprint found in DNS");
		ಇಲ್ಲದಿದ್ದರೆ
			debug("mismatching host key fingerprint found in DNS");
	ಇಲ್ಲದಿದ್ದರೆ
		debug("no host key fingerprint found in DNS");

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
ಪೂರ್ಣಾಂಕ
export_dns_rr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ರಚನೆ sshkey *ಕೀಲಿ, FILE *f, ಪೂರ್ಣಾಂಕ generic,
    ಪೂರ್ಣಾಂಕ alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	ಗಾತ್ರ_t i, rdata_digest_len;
	ಪೂರ್ಣಾಂಕ success = 0;

	ಗಾಗಿ (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ಆದರೆ (alg != -1 && dtype != alg)
			ಮುಂದುವರಿ;
		rdata_digest_type = dtype;
		ಆದರೆ (dns_read_ಕೀಲಿ(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, ಕೀಲಿ)) {
			ಆದರೆ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			ಗಾಗಿ (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			ಬಿಡುಗಡೆ(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ಆದರೆ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	ಹಿಂತಿರುಗಿ success;
}
