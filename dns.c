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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "dns.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "digest.h"

நிலையான மாறிலி எழுத்து * மாறிலி errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

நிலையான மாறிலி எழுத்து *
dns_result_totext(unsigned முழு res)
{
	தேர்வு (res) {
	நிலை ERRSET_SUCCESS:
		திரும்பு errset_text[ERRSET_SUCCESS];
	நிலை ERRSET_NOMEMORY:
		திரும்பு errset_text[ERRSET_NOMEMORY];
	நிலை ERRSET_FAIL:
		திரும்பு errset_text[ERRSET_FAIL];
	நிலை ERRSET_INVAL:
		திரும்பு errset_text[ERRSET_INVAL];
	நிலை ERRSET_NONAME:
		திரும்பு errset_text[ERRSET_NONAME];
	நிலை ERRSET_NODATA:
		திரும்பு errset_text[ERRSET_NODATA];
	இயல்பு:
		திரும்பு "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
நிலையான முழு
dns_read_சாவி(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, கட்டமைப்பு sshkey *சாவி)
{
	முழு r, success = 0;
	முழு fp_alg = -1;

	தேர்வு (சாவி->type) {
	நிலை சாவி_RSA:
		*algorithm = SSHFP_சாவி_RSA;
		நிறுத்து;
	நிலை சாவி_ECDSA:
		*algorithm = SSHFP_சாவி_ECDSA;
		நிறுத்து;
	நிலை சாவி_ED25519:
		*algorithm = SSHFP_சாவி_ED25519;
		நிறுத்து;
	இயல்பு:
		*algorithm = SSHFP_சாவி_RESERVED; /* 0 */
	}

	தேர்வு (*digest_type) {
	நிலை SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		நிறுத்து;
	நிலை SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		நிறுத்து;
	இயல்பு:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	எனில் (*algorithm && *digest_type) {
		எனில் ((r = sshkey_fingerprint_raw(சாவி, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} இல்லையெனில் {
		*digest = வெற்று;
		*digest_len = 0;
	}

	திரும்பு success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
நிலையான முழு
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, முழு rdata_len)
{
	முழு success = 0;

	*algorithm = SSHFP_சாவி_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	எனில் (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		எனில் (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} இல்லையெனில் {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	திரும்பு success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
நிலையான முழு
is_numeric_hostname(மாறிலி எழுத்து *hostname)
{
	கட்டமைப்பு addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	எனில் (hostname == வெற்று) {
		error("is_numeric_hostname called with NULL hostname");
		திரும்பு -1;
	}

	memset(&hints, 0, அளவு(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	எனில் (getaddrinfo(hostname, வெற்று, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		திரும்பு -1;
	}

	திரும்பு 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
முழு
verify_host_சாவி_dns(மாறிலி எழுத்து *hostname, கட்டமைப்பு sockaddr *address,
    கட்டமைப்பு sshkey *hostkey, முழு *flags)
{
	u_int counter;
	முழு result;
	கட்டமைப்பு rrsetinfo *fingerprints = வெற்று;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	எனில் (hostkey == வெற்று)
		fatal("No key to look up!");

	எனில் (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		திரும்பு -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	எனில் (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		திரும்பு -1;
	}

	எனில் (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} இல்லையெனில் {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	எனில் (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	க்கு (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		எனில் (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			தொடர்;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		எனில் (!dns_read_சாவி(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			விடுவி(dnskey_digest);
			freerrset(fingerprints);
			திரும்பு -1;
		}

		/* Check if the current key is the same as the given key */
		எனில் (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			எனில் (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} இல்லையெனில் {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		விடுவி(dnskey_digest);
		விடுவி(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	எனில் (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	எனில் (*flags & DNS_VERIFY_FOUND)
		எனில் (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		இல்லையெனில்
			debug("mismatching host key fingerprint found in DNS");
	இல்லையெனில்
		debug("no host key fingerprint found in DNS");

	திரும்பு 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
முழு
export_dns_rr(மாறிலி எழுத்து *hostname, கட்டமைப்பு sshkey *சாவி, FILE *f, முழு generic,
    முழு alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	முழு success = 0;

	க்கு (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		எனில் (alg != -1 && dtype != alg)
			தொடர்;
		rdata_digest_type = dtype;
		எனில் (dns_read_சாவி(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, சாவி)) {
			எனில் (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} இல்லையெனில் {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			க்கு (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			விடுவி(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	எனில் (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	திரும்பு success;
}
