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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "dns.h"
#include "log.h"
#include "digest.h"

static const char * const errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

static const char *
dns_result_totext(unsigned số_nguyên res)
{
	switch (res) {
	case ERRSET_SUCCESS:
		trả_về errset_text[ERRSET_SUCCESS];
	case ERRSET_NOMEMORY:
		trả_về errset_text[ERRSET_NOMEMORY];
	case ERRSET_FAIL:
		trả_về errset_text[ERRSET_FAIL];
	case ERRSET_INVAL:
		trả_về errset_text[ERRSET_INVAL];
	case ERRSET_NONAME:
		trả_về errset_text[ERRSET_NONAME];
	case ERRSET_NODATA:
		trả_về errset_text[ERRSET_NODATA];
	default:
		trả_về "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
static số_nguyên
dns_read_key(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, struct sshkey *key)
{
	số_nguyên r, success = 0;
	số_nguyên fp_alg = -1;

	switch (key->type) {
	case KEY_RSA:
		*algorithm = SSHFP_KEY_RSA;
		break;
	case KEY_ECDSA:
		*algorithm = SSHFP_KEY_ECDSA;
		break;
	case KEY_ED25519:
		*algorithm = SSHFP_KEY_ED25519;
		break;
	default:
		*algorithm = SSHFP_KEY_RESERVED; /* 0 */
	}

	switch (*digest_type) {
	case SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		break;
	case SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		break;
	default:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	nếu (*algorithm && *digest_type) {
		nếu ((r = sshkey_fingerprint_raw(key, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} không_thì {
		*digest = NULL;
		*digest_len = 0;
	}

	trả_về success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
static số_nguyên
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, số_nguyên rdata_len)
{
	số_nguyên success = 0;

	*algorithm = SSHFP_KEY_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	nếu (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		nếu (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} không_thì {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	trả_về success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
static số_nguyên
is_numeric_hostname(const char *hostname)
{
	struct addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	nếu (hostname == NULL) {
		error("is_numeric_hostname called with NULL hostname");
		trả_về -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	nếu (getaddrinfo(hostname, NULL, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		trả_về -1;
	}

	trả_về 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
số_nguyên
verify_host_key_dns(const char *hostname, struct sockaddr *address,
    struct sshkey *hostkey, số_nguyên *flags)
{
	u_int counter;
	số_nguyên result;
	struct rrsetinfo *fingerprints = NULL;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	nếu (hostkey == NULL)
		fatal("No key to look up!");

	nếu (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		trả_về -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	nếu (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		trả_về -1;
	}

	nếu (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} không_thì {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	nếu (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	cho (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		nếu (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			continue;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		nếu (!dns_read_key(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			free(dnskey_digest);
			freerrset(fingerprints);
			trả_về -1;
		}

		/* Check if the current key is the same as the given key */
		nếu (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			nếu (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} không_thì {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		free(dnskey_digest);
		free(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	nếu (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	nếu (*flags & DNS_VERIFY_FOUND)
		nếu (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		không_thì
			debug("mismatching host key fingerprint found in DNS");
	không_thì
		debug("no host key fingerprint found in DNS");

	trả_về 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
số_nguyên
export_dns_rr(const char *hostname, struct sshkey *key, FILE *f, số_nguyên generic,
    số_nguyên alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	số_nguyên success = 0;

	cho (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		nếu (alg != -1 && dtype != alg)
			continue;
		rdata_digest_type = dtype;
		nếu (dns_read_key(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, key)) {
			nếu (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} không_thì {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			cho (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			free(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	nếu (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	trả_về success;
}
