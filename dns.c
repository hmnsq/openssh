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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "dns.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "digest.h"

স্থির ধ্রুব বর্ণ * ধ্রুব errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

স্থির ধ্রুব বর্ণ *
dns_result_totext(unsigned পূর্ণাঙ্ক res)
{
	বিকল্প (res) {
	পক্ষ ERRSET_SUCCESS:
		প্রত্যাগম errset_text[ERRSET_SUCCESS];
	পক্ষ ERRSET_NOMEMORY:
		প্রত্যাগম errset_text[ERRSET_NOMEMORY];
	পক্ষ ERRSET_FAIL:
		প্রত্যাগম errset_text[ERRSET_FAIL];
	পক্ষ ERRSET_INVAL:
		প্রত্যাগম errset_text[ERRSET_INVAL];
	পক্ষ ERRSET_NONAME:
		প্রত্যাগম errset_text[ERRSET_NONAME];
	পক্ষ ERRSET_NODATA:
		প্রত্যাগম errset_text[ERRSET_NODATA];
	স্বভাব:
		প্রত্যাগম "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
স্থির পূর্ণাঙ্ক
dns_read_চাবি(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r, success = 0;
	পূর্ণাঙ্ক fp_alg = -1;

	বিকল্প (চাবি->type) {
	পক্ষ চাবি_RSA:
		*algorithm = SSHFP_চাবি_RSA;
		ভঙ্গ;
	পক্ষ চাবি_ECDSA:
		*algorithm = SSHFP_চাবি_ECDSA;
		ভঙ্গ;
	পক্ষ চাবি_ED25519:
		*algorithm = SSHFP_চাবি_ED25519;
		ভঙ্গ;
	স্বভাব:
		*algorithm = SSHFP_চাবি_RESERVED; /* 0 */
	}

	বিকল্প (*digest_type) {
	পক্ষ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ভঙ্গ;
	পক্ষ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ভঙ্গ;
	স্বভাব:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	যদি (*algorithm && *digest_type) {
		যদি ((r = sshkey_fingerprint_raw(চাবি, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} অন্যথা {
		*digest = রিক্ত;
		*digest_len = 0;
	}

	প্রত্যাগম success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
স্থির পূর্ণাঙ্ক
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, পূর্ণাঙ্ক rdata_len)
{
	পূর্ণাঙ্ক success = 0;

	*algorithm = SSHFP_চাবি_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	যদি (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		যদি (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} অন্যথা {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	প্রত্যাগম success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
স্থির পূর্ণাঙ্ক
is_numeric_hostname(ধ্রুব বর্ণ *hostname)
{
	সংরচনা addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	যদি (hostname == রিক্ত) {
		error("is_numeric_hostname called with NULL hostname");
		প্রত্যাগম -1;
	}

	memset(&hints, 0, পরিমাণ(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	যদি (getaddrinfo(hostname, রিক্ত, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		প্রত্যাগম -1;
	}

	প্রত্যাগম 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
পূর্ণাঙ্ক
verify_host_চাবি_dns(ধ্রুব বর্ণ *hostname, সংরচনা sockaddr *address,
    সংরচনা sshkey *hostkey, পূর্ণাঙ্ক *flags)
{
	u_int counter;
	পূর্ণাঙ্ক result;
	সংরচনা rrsetinfo *fingerprints = রিক্ত;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	যদি (hostkey == রিক্ত)
		fatal("No key to look up!");

	যদি (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		প্রত্যাগম -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	যদি (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		প্রত্যাগম -1;
	}

	যদি (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} অন্যথা {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	যদি (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	প্রতি (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		যদি (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			অনুবর্ত;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		যদি (!dns_read_চাবি(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			মুক্ত(dnskey_digest);
			freerrset(fingerprints);
			প্রত্যাগম -1;
		}

		/* Check if the current key is the same as the given key */
		যদি (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			যদি (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} অন্যথা {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		মুক্ত(dnskey_digest);
		মুক্ত(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	যদি (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	যদি (*flags & DNS_VERIFY_FOUND)
		যদি (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		অন্যথা
			debug("mismatching host key fingerprint found in DNS");
	অন্যথা
		debug("no host key fingerprint found in DNS");

	প্রত্যাগম 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
পূর্ণাঙ্ক
export_dns_rr(ধ্রুব বর্ণ *hostname, সংরচনা sshkey *চাবি, FILE *f, পূর্ণাঙ্ক generic,
    পূর্ণাঙ্ক alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	পূর্ণাঙ্ক success = 0;

	প্রতি (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		যদি (alg != -1 && dtype != alg)
			অনুবর্ত;
		rdata_digest_type = dtype;
		যদি (dns_read_চাবি(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, চাবি)) {
			যদি (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} অন্যথা {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			প্রতি (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			মুক্ত(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	যদি (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	প্রত্যাগম success;
}
