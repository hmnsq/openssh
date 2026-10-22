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

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
dns_result_totext(unsigned ಪೂರ್ಣಾಙ್ಕ res)
{
	ವಿಕಲ್ಪ (res) {
	ಪಕ್ಷ ERRSET_SUCCESS:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_SUCCESS];
	ಪಕ್ಷ ERRSET_NOMEMORY:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_NOMEMORY];
	ಪಕ್ಷ ERRSET_FAIL:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_FAIL];
	ಪಕ್ಷ ERRSET_INVAL:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_INVAL];
	ಪಕ್ಷ ERRSET_NONAME:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_NONAME];
	ಪಕ್ಷ ERRSET_NODATA:
		ಪ್ರತ್ಯಾಗಮ errset_text[ERRSET_NODATA];
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
dns_read_ಕೀಲಿ(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ಪೂರ್ಣಾಙ್ಕ fp_alg = -1;

	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		*algorithm = SSHFP_ಕೀಲಿ_RSA;
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		*algorithm = SSHFP_ಕೀಲಿ_ECDSA;
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
		*algorithm = SSHFP_ಕೀಲಿ_ED25519;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		*algorithm = SSHFP_ಕೀಲಿ_RESERVED; /* 0 */
	}

	ವಿಕಲ್ಪ (*digest_type) {
	ಪಕ್ಷ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ಯದಿ (*algorithm && *digest_type) {
		ಯದಿ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ಅನ್ಯಥಾ {
		*digest = ರಿಕ್ತ;
		*digest_len = 0;
	}

	ಪ್ರತ್ಯಾಗಮ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, ಪೂರ್ಣಾಙ್ಕ rdata_len)
{
	ಪೂರ್ಣಾಙ್ಕ success = 0;

	*algorithm = SSHFP_ಕೀಲಿ_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ಯದಿ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ಯದಿ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} ಅನ್ಯಥಾ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	ಪ್ರತ್ಯಾಗಮ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_numeric_hostname(ಧ್ರುವ ವರ್ಣ *hostname)
{
	ಸಂರಚನಾ addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ಯದಿ (hostname == ರಿಕ್ತ) {
		error("is_numeric_hostname called with NULL hostname");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ಯದಿ (getaddrinfo(hostname, ರಿಕ್ತ, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
ಪೂರ್ಣಾಙ್ಕ
verify_host_ಕೀಲಿ_dns(ಧ್ರುವ ವರ್ಣ *hostname, ಸಂರಚನಾ sockaddr *address,
    ಸಂರಚನಾ sshkey *hostkey, ಪೂರ್ಣಾಙ್ಕ *flags)
{
	u_int counter;
	ಪೂರ್ಣಾಙ್ಕ result;
	ಸಂರಚನಾ rrsetinfo *fingerprints = ರಿಕ್ತ;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ಯದಿ (hostkey == ರಿಕ್ತ)
		fatal("No key to look up!");

	ಯದಿ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ಯದಿ (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ಅನ್ಯಥಾ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ಯದಿ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	ಪ್ರತಿ (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ಯದಿ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			ಅನುವರ್ತ;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ಯದಿ (!dns_read_ಕೀಲಿ(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			ಮುಕ್ತ(dnskey_digest);
			freerrset(fingerprints);
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		/* Check if the current key is the same as the given key */
		ಯದಿ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ಯದಿ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} ಅನ್ಯಥಾ {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		ಮುಕ್ತ(dnskey_digest);
		ಮುಕ್ತ(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	ಯದಿ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	ಯದಿ (*flags & DNS_VERIFY_FOUND)
		ಯದಿ (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		ಅನ್ಯಥಾ
			debug("mismatching host key fingerprint found in DNS");
	ಅನ್ಯಥಾ
		debug("no host key fingerprint found in DNS");

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
ಪೂರ್ಣಾಙ್ಕ
export_dns_rr(ಧ್ರುವ ವರ್ಣ *hostname, ಸಂರಚನಾ sshkey *ಕೀಲಿ, FILE *f, ಪೂರ್ಣಾಙ್ಕ generic,
    ಪೂರ್ಣಾಙ್ಕ alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	ಪೂರ್ಣಾಙ್ಕ success = 0;

	ಪ್ರತಿ (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ಯದಿ (alg != -1 && dtype != alg)
			ಅನುವರ್ತ;
		rdata_digest_type = dtype;
		ಯದಿ (dns_read_ಕೀಲಿ(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, ಕೀಲಿ)) {
			ಯದಿ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ಅನ್ಯಥಾ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			ಪ್ರತಿ (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			ಮುಕ್ತ(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ಯದಿ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	ಪ್ರತ್ಯಾಗಮ success;
}
