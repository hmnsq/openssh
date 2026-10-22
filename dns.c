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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "digest.h"

स्थिर ध्रुव वर्ण * ध्रुव errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

स्थिर ध्रुव वर्ण *
dns_result_totext(unsigned पूर्णाङ्क res)
{
	विकल्प (res) {
	पक्ष ERRSET_SUCCESS:
		पटिनिवत्त errset_text[ERRSET_SUCCESS];
	पक्ष ERRSET_NOMEMORY:
		पटिनिवत्त errset_text[ERRSET_NOMEMORY];
	पक्ष ERRSET_FAIL:
		पटिनिवत्त errset_text[ERRSET_FAIL];
	पक्ष ERRSET_INVAL:
		पटिनिवत्त errset_text[ERRSET_INVAL];
	पक्ष ERRSET_NONAME:
		पटिनिवत्त errset_text[ERRSET_NONAME];
	पक्ष ERRSET_NODATA:
		पटिनिवत्त errset_text[ERRSET_NODATA];
	स्वभाव:
		पटिनिवत्त "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
स्थिर पूर्णाङ्क
dns_read_कुञ्चिका(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r, success = 0;
	पूर्णाङ्क fp_alg = -1;

	विकल्प (कुञ्चिका->type) {
	पक्ष कुञ्चिका_RSA:
		*algorithm = SSHFP_कुञ्चिका_RSA;
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		*algorithm = SSHFP_कुञ्चिका_ECDSA;
		भङ्ग;
	पक्ष कुञ्चिका_ED25519:
		*algorithm = SSHFP_कुञ्चिका_ED25519;
		भङ्ग;
	स्वभाव:
		*algorithm = SSHFP_कुञ्चिका_RESERVED; /* 0 */
	}

	विकल्प (*digest_type) {
	पक्ष SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		भङ्ग;
	पक्ष SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		भङ्ग;
	स्वभाव:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	सचे (*algorithm && *digest_type) {
		सचे ((r = sshkey_fingerprint_raw(कुञ्चिका, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} अञ्ञथा {
		*digest = रिक्त;
		*digest_len = 0;
	}

	पटिनिवत्त success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
स्थिर पूर्णाङ्क
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, पूर्णाङ्क rdata_len)
{
	पूर्णाङ्क success = 0;

	*algorithm = SSHFP_कुञ्चिका_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	सचे (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		सचे (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} अञ्ञथा {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	पटिनिवत्त success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
स्थिर पूर्णाङ्क
is_numeric_hostname(ध्रुव वर्ण *hostname)
{
	संरचना addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	सचे (hostname == रिक्त) {
		error("is_numeric_hostname called with NULL hostname");
		पटिनिवत्त -1;
	}

	memset(&hints, 0, परिमाण(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	सचे (getaddrinfo(hostname, रिक्त, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		पटिनिवत्त -1;
	}

	पटिनिवत्त 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
पूर्णाङ्क
verify_host_कुञ्चिका_dns(ध्रुव वर्ण *hostname, संरचना sockaddr *address,
    संरचना sshkey *hostkey, पूर्णाङ्क *flags)
{
	u_int counter;
	पूर्णाङ्क result;
	संरचना rrsetinfo *fingerprints = रिक्त;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	सचे (hostkey == रिक्त)
		fatal("No key to look up!");

	सचे (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		पटिनिवत्त -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	सचे (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		पटिनिवत्त -1;
	}

	सचे (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} अञ्ञथा {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	सचे (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	अत्थाय (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		सचे (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			अनुवर्त;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		सचे (!dns_read_कुञ्चिका(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			मुक्त(dnskey_digest);
			freerrset(fingerprints);
			पटिनिवत्त -1;
		}

		/* Check if the current key is the same as the given key */
		सचे (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			सचे (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} अञ्ञथा {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		मुक्त(dnskey_digest);
		मुक्त(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	सचे (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	सचे (*flags & DNS_VERIFY_FOUND)
		सचे (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		अञ्ञथा
			debug("mismatching host key fingerprint found in DNS");
	अञ्ञथा
		debug("no host key fingerprint found in DNS");

	पटिनिवत्त 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
पूर्णाङ्क
export_dns_rr(ध्रुव वर्ण *hostname, संरचना sshkey *कुञ्चिका, FILE *f, पूर्णाङ्क generic,
    पूर्णाङ्क alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	पूर्णाङ्क success = 0;

	अत्थाय (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		सचे (alg != -1 && dtype != alg)
			अनुवर्त;
		rdata_digest_type = dtype;
		सचे (dns_read_कुञ्चिका(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, कुञ्चिका)) {
			सचे (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} अञ्ञथा {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			अत्थाय (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			मुक्त(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	सचे (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	पटिनिवत्त success;
}
