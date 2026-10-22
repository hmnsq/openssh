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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "dns.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
dns_result_totext(unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା res)
{
	ବାଛ (res) {
	ସ୍ଥିତି ERRSET_SUCCESS:
		ଫେରନ୍ତୁ errset_text[ERRSET_SUCCESS];
	ସ୍ଥିତି ERRSET_NOMEMORY:
		ଫେରନ୍ତୁ errset_text[ERRSET_NOMEMORY];
	ସ୍ଥିତି ERRSET_FAIL:
		ଫେରନ୍ତୁ errset_text[ERRSET_FAIL];
	ସ୍ଥିତି ERRSET_INVAL:
		ଫେରନ୍ତୁ errset_text[ERRSET_INVAL];
	ସ୍ଥିତି ERRSET_NONAME:
		ଫେରନ୍ତୁ errset_text[ERRSET_NONAME];
	ସ୍ଥିତି ERRSET_NODATA:
		ଫେରନ୍ତୁ errset_text[ERRSET_NODATA];
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dns_read_ଚାବି(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fp_alg = -1;

	ବାଛ (ଚାବି->type) {
	ସ୍ଥିତି ଚାବି_RSA:
		*algorithm = SSHFP_ଚାବି_RSA;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		*algorithm = SSHFP_ଚାବି_ECDSA;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ED25519:
		*algorithm = SSHFP_ଚାବି_ED25519;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		*algorithm = SSHFP_ଚାବି_RESERVED; /* 0 */
	}

	ବାଛ (*digest_type) {
	ସ୍ଥିତି SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ଯଦି (*algorithm && *digest_type) {
		ଯଦି ((r = sshkey_fingerprint_raw(ଚାବି, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ଅନ୍ୟଥା {
		*digest = ଖାଲି;
		*digest_len = 0;
	}

	ଫେରନ୍ତୁ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdata_len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0;

	*algorithm = SSHFP_ଚାବି_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ଯଦି (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ଯଦି (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} ଅନ୍ୟଥା {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	ଫେରନ୍ତୁ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_numeric_hostname(ଅଚଳ ଅକ୍ଷର *hostname)
{
	ସଂରଚନା addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ଯଦି (hostname == ଖାଲି) {
		error("is_numeric_hostname called with NULL hostname");
		ଫେରନ୍ତୁ -1;
	}

	memset(&hints, 0, ଆକାର(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ଯଦି (getaddrinfo(hostname, ଖାଲି, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ଫେରନ୍ତୁ -1;
	}

	ଫେରନ୍ତୁ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
verify_host_ଚାବି_dns(ଅଚଳ ଅକ୍ଷର *hostname, ସଂରଚନା sockaddr *address,
    ସଂରଚନା sshkey *hostkey, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *flags)
{
	u_int counter;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result;
	ସଂରଚନା rrsetinfo *fingerprints = ଖାଲି;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ଯଦି (hostkey == ଖାଲି)
		fatal("No key to look up!");

	ଯଦି (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ଫେରନ୍ତୁ -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ଯଦି (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ଅନ୍ୟଥା {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ଯଦି (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	ପାଇଁ (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ଯଦି (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			ଜାରି;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ଯଦି (!dns_read_ଚାବି(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			ମୁକ୍ତ(dnskey_digest);
			freerrset(fingerprints);
			ଫେରନ୍ତୁ -1;
		}

		/* Check if the current key is the same as the given key */
		ଯଦି (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ଯଦି (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} ଅନ୍ୟଥା {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		ମୁକ୍ତ(dnskey_digest);
		ମୁକ୍ତ(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	ଯଦି (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	ଯଦି (*flags & DNS_VERIFY_FOUND)
		ଯଦି (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		ଅନ୍ୟଥା
			debug("mismatching host key fingerprint found in DNS");
	ଅନ୍ୟଥା
		debug("no host key fingerprint found in DNS");

	ଫେରନ୍ତୁ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
export_dns_rr(ଅଚଳ ଅକ୍ଷର *hostname, ସଂରଚନା sshkey *ଚାବି, FILE *f, ପୂର୍ଣ୍ଣସଂଖ୍ୟା generic,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0;

	ପାଇଁ (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ଯଦି (alg != -1 && dtype != alg)
			ଜାରି;
		rdata_digest_type = dtype;
		ଯଦି (dns_read_ଚାବି(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, ଚାବି)) {
			ଯଦି (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ଅନ୍ୟଥା {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			ପାଇଁ (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			ମୁକ୍ତ(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ଯଦି (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	ଫେରନ୍ତୁ success;
}
