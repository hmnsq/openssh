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

স্থির ধ্রুবক অক্ষর * ধ্রুবক errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

স্থির ধ্রুবক অক্ষর *
dns_ফলাফল_totext(unsigned পূর্ণসংখ্যা res)
{
	নির্বাচন (res) {
	ক্ষেত্র ERRSET_SUCCESS:
		ফেরত errset_text[ERRSET_SUCCESS];
	ক্ষেত্র ERRSET_NOMEMORY:
		ফেরত errset_text[ERRSET_NOMEMORY];
	ক্ষেত্র ERRSET_FAIL:
		ফেরত errset_text[ERRSET_FAIL];
	ক্ষেত্র ERRSET_INVAL:
		ফেরত errset_text[ERRSET_INVAL];
	ক্ষেত্র ERRSET_NONAME:
		ফেরত errset_text[ERRSET_NONAME];
	ক্ষেত্র ERRSET_NODATA:
		ফেরত errset_text[ERRSET_NODATA];
	পূর্বনির্ধারিত:
		ফেরত "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
স্থির পূর্ণসংখ্যা
dns_read_চাবি(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, আকার_t *digest_len, কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r, success = 0;
	পূর্ণসংখ্যা fp_alg = -1;

	নির্বাচন (চাবি->type) {
	ক্ষেত্র চাবি_RSA:
		*algorithm = SSHFP_চাবি_RSA;
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		*algorithm = SSHFP_চাবি_ECDSA;
		বিরতি;
	ক্ষেত্র চাবি_ED25519:
		*algorithm = SSHFP_চাবি_ED25519;
		বিরতি;
	পূর্বনির্ধারিত:
		*algorithm = SSHFP_চাবি_RESERVED; /* 0 */
	}

	নির্বাচন (*digest_type) {
	ক্ষেত্র SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		বিরতি;
	ক্ষেত্র SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		বিরতি;
	পূর্বনির্ধারিত:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	যদি (*algorithm && *digest_type) {
		যদি ((r = sshkey_fingerprint_raw(চাবি, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} অন্যথা {
		*digest = ফাঁকা;
		*digest_len = 0;
	}

	ফেরত success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
স্থির পূর্ণসংখ্যা
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, আকার_t *digest_len, u_char *rdata, পূর্ণসংখ্যা rdata_len)
{
	পূর্ণসংখ্যা success = 0;

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

	ফেরত success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
স্থির পূর্ণসংখ্যা
is_numeric_hostname(ধ্রুবক অক্ষর *hostname)
{
	কাঠামো addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	যদি (hostname == ফাঁকা) {
		error("is_numeric_hostname called with NULL hostname");
		ফেরত -1;
	}

	memset(&hints, 0, আকার(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	যদি (getaddrinfo(hostname, ফাঁকা, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ফেরত -1;
	}

	ফেরত 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
পূর্ণসংখ্যা
verify_host_চাবি_dns(ধ্রুবক অক্ষর *hostname, কাঠামো sockaddr *address,
    কাঠামো sshkey *hostkey, পূর্ণসংখ্যা *flags)
{
	u_int গণক;
	পূর্ণসংখ্যা ফলাফল;
	কাঠামো rrsetinfo *fingerprints = ফাঁকা;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	আকার_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	আকার_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	যদি (hostkey == ফাঁকা)
		fatal("No key to look up!");

	যদি (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ফেরত -1;
	}

	ফলাফল = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	যদি (ফলাফল) {
		verbose("DNS lookup error: %s", dns_ফলাফল_totext(ফলাফল));
		ফেরত -1;
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

	জন্য (গণক = 0; গণক < fingerprints->rri_nrdatas; গণক++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		যদি (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[গণক].rdi_তথ্য,
		    fingerprints->rri_rdatas[গণক].rdi_দৈর্ঘ্য)) {
			verbose("Error parsing fingerprint from DNS.");
			চালু;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		যদি (!dns_read_চাবি(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			মুক্ত(dnskey_digest);
			freerrset(fingerprints);
			ফেরত -1;
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

	ফেরত 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
পূর্ণসংখ্যা
export_dns_rr(ধ্রুবক অক্ষর *hostname, কাঠামো sshkey *চাবি, FILE *f, পূর্ণসংখ্যা generic,
    পূর্ণসংখ্যা alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	আকার_t i, rdata_digest_len;
	পূর্ণসংখ্যা success = 0;

	জন্য (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		যদি (alg != -1 && dtype != alg)
			চালু;
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
			জন্য (i = 0; i < rdata_digest_len; i++)
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

	ফেরত success;
}
