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

static const var_na * const errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

static const var_na *
dns_result_totext(unsigned puur_naa_nka res)
{
	switch (res) {
	pak_sa ERRSET_SUCCESS:
		ᬯᬮᬶ errset_text[ERRSET_SUCCESS];
	pak_sa ERRSET_NOMEMORY:
		ᬯᬮᬶ errset_text[ERRSET_NOMEMORY];
	pak_sa ERRSET_FAIL:
		ᬯᬮᬶ errset_text[ERRSET_FAIL];
	pak_sa ERRSET_INVAL:
		ᬯᬮᬶ errset_text[ERRSET_INVAL];
	pak_sa ERRSET_NONAME:
		ᬯᬮᬶ errset_text[ERRSET_NONAME];
	pak_sa ERRSET_NODATA:
		ᬯᬮᬶ errset_text[ERRSET_NODATA];
	default:
		ᬯᬮᬶ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
static puur_naa_nka
dns_read_key(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, sa_nracanaa sshkey *key)
{
	puur_naa_nka r, success = 0;
	puur_naa_nka fp_alg = -1;

	switch (key->type) {
	pak_sa KEY_RSA:
		*algorithm = SSHFP_KEY_RSA;
		bha_nga;
	pak_sa KEY_ECDSA:
		*algorithm = SSHFP_KEY_ECDSA;
		bha_nga;
	pak_sa KEY_ED25519:
		*algorithm = SSHFP_KEY_ED25519;
		bha_nga;
	default:
		*algorithm = SSHFP_KEY_RESERVED; /* 0 */
	}

	switch (*digest_type) {
	pak_sa SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		bha_nga;
	pak_sa SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		bha_nga;
	default:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ᬬᬾᬦ᭄ (*algorithm && *digest_type) {
		ᬬᬾᬦ᭄ ((r = sshkey_fingerprint_raw(key, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ᬮᬶᬬ {
		*digest = NULL;
		*digest_len = 0;
	}

	ᬯᬮᬶ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
static puur_naa_nka
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, puur_naa_nka rdata_len)
{
	puur_naa_nka success = 0;

	*algorithm = SSHFP_KEY_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ᬬᬾᬦ᭄ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ᬬᬾᬦ᭄ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} ᬮᬶᬬ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	ᬯᬮᬶ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
static puur_naa_nka
is_numeric_hostname(const var_na *hostname)
{
	sa_nracanaa addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ᬬᬾᬦ᭄ (hostname == NULL) {
		error("is_numeric_hostname called with NULL hostname");
		ᬯᬮᬶ -1;
	}

	memset(&hints, 0, parimaa_na(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ᬬᬾᬦ᭄ (getaddrinfo(hostname, NULL, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ᬯᬮᬶ -1;
	}

	ᬯᬮᬶ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
puur_naa_nka
verify_host_key_dns(const var_na *hostname, sa_nracanaa sockaddr *address,
    sa_nracanaa sshkey *hostkey, puur_naa_nka *flags)
{
	u_int counter;
	puur_naa_nka result;
	sa_nracanaa rrsetinfo *fingerprints = NULL;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ᬬᬾᬦ᭄ (hostkey == NULL)
		fatal("No key to look up!");

	ᬬᬾᬦ᭄ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ᬯᬮᬶ -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ᬬᬾᬦ᭄ (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		ᬯᬮᬶ -1;
	}

	ᬬᬾᬦ᭄ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ᬮᬶᬬ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ᬬᬾᬦ᭄ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	for (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ᬬᬾᬦ᭄ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			continue;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ᬬᬾᬦ᭄ (!dns_read_key(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			free(dnskey_digest);
			freerrset(fingerprints);
			ᬯᬮᬶ -1;
		}

		/* Check if the current key is the same as the given key */
		ᬬᬾᬦ᭄ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ᬬᬾᬦ᭄ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} ᬮᬶᬬ {
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
	ᬬᬾᬦ᭄ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	ᬬᬾᬦ᭄ (*flags & DNS_VERIFY_FOUND)
		ᬬᬾᬦ᭄ (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		ᬮᬶᬬ
			debug("mismatching host key fingerprint found in DNS");
	ᬮᬶᬬ
		debug("no host key fingerprint found in DNS");

	ᬯᬮᬶ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
puur_naa_nka
export_dns_rr(const var_na *hostname, sa_nracanaa sshkey *key, FILE *f, puur_naa_nka generic,
    puur_naa_nka alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	puur_naa_nka success = 0;

	for (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ᬬᬾᬦ᭄ (alg != -1 && dtype != alg)
			continue;
		rdata_digest_type = dtype;
		ᬬᬾᬦ᭄ (dns_read_key(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, key)) {
			ᬬᬾᬦ᭄ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ᬮᬶᬬ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			for (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			free(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ᬬᬾᬦ᭄ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	ᬯᬮᬶ success;
}
