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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "dns.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "digest.h"

સ્થિર અચલ અક્ષર * અચલ errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

સ્થિર અચલ અક્ષર *
dns_result_totext(unsigned પૂર્ણાંક res)
{
	પસંદગી (res) {
	સ્થિતિ ERRSET_SUCCESS:
		પાછા errset_text[ERRSET_SUCCESS];
	સ્થિતિ ERRSET_NOMEMORY:
		પાછા errset_text[ERRSET_NOMEMORY];
	સ્થિતિ ERRSET_FAIL:
		પાછા errset_text[ERRSET_FAIL];
	સ્થિતિ ERRSET_INVAL:
		પાછા errset_text[ERRSET_INVAL];
	સ્થિતિ ERRSET_NONAME:
		પાછા errset_text[ERRSET_NONAME];
	સ્થિતિ ERRSET_NODATA:
		પાછા errset_text[ERRSET_NODATA];
	મૂળભૂત:
		પાછા "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
સ્થિર પૂર્ણાંક
dns_read_ચાવી(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r, success = 0;
	પૂર્ણાંક fp_alg = -1;

	પસંદગી (ચાવી->type) {
	સ્થિતિ ચાવી_RSA:
		*algorithm = SSHFP_ચાવી_RSA;
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		*algorithm = SSHFP_ચાવી_ECDSA;
		તોડો;
	સ્થિતિ ચાવી_ED25519:
		*algorithm = SSHFP_ચાવી_ED25519;
		તોડો;
	મૂળભૂત:
		*algorithm = SSHFP_ચાવી_RESERVED; /* 0 */
	}

	પસંદગી (*digest_type) {
	સ્થિતિ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		તોડો;
	સ્થિતિ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		તોડો;
	મૂળભૂત:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	જો (*algorithm && *digest_type) {
		જો ((r = sshkey_fingerprint_raw(ચાવી, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} નહીંતર {
		*digest = ખાલી;
		*digest_len = 0;
	}

	પાછા success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
સ્થિર પૂર્ણાંક
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, પૂર્ણાંક rdata_len)
{
	પૂર્ણાંક success = 0;

	*algorithm = SSHFP_ચાવી_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	જો (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		જો (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} નહીંતર {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	પાછા success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
સ્થિર પૂર્ણાંક
is_numeric_hostname(અચલ અક્ષર *hostname)
{
	સંરચના addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	જો (hostname == ખાલી) {
		error("is_numeric_hostname called with NULL hostname");
		પાછા -1;
	}

	memset(&hints, 0, કદ(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	જો (getaddrinfo(hostname, ખાલી, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		પાછા -1;
	}

	પાછા 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
પૂર્ણાંક
verify_host_ચાવી_dns(અચલ અક્ષર *hostname, સંરચના sockaddr *address,
    સંરચના sshkey *hostkey, પૂર્ણાંક *flags)
{
	u_int counter;
	પૂર્ણાંક result;
	સંરચના rrsetinfo *fingerprints = ખાલી;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	જો (hostkey == ખાલી)
		fatal("No key to look up!");

	જો (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		પાછા -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	જો (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		પાછા -1;
	}

	જો (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} નહીંતર {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	જો (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	માટે (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		જો (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			ચાલુ;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		જો (!dns_read_ચાવી(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			મુક્ત(dnskey_digest);
			freerrset(fingerprints);
			પાછા -1;
		}

		/* Check if the current key is the same as the given key */
		જો (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			જો (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} નહીંતર {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		મુક્ત(dnskey_digest);
		મુક્ત(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	જો (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	જો (*flags & DNS_VERIFY_FOUND)
		જો (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		નહીંતર
			debug("mismatching host key fingerprint found in DNS");
	નહીંતર
		debug("no host key fingerprint found in DNS");

	પાછા 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
પૂર્ણાંક
export_dns_rr(અચલ અક્ષર *hostname, સંરચના sshkey *ચાવી, FILE *f, પૂર્ણાંક generic,
    પૂર્ણાંક alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	પૂર્ણાંક success = 0;

	માટે (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		જો (alg != -1 && dtype != alg)
			ચાલુ;
		rdata_digest_type = dtype;
		જો (dns_read_ચાવી(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, ચાવી)) {
			જો (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} નહીંતર {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			માટે (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			મુક્ત(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	જો (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	પાછા success;
}
