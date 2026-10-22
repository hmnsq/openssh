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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "dns.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "digest.h"

స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి errset_పాఠ్యం[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

స్థిర స్థిరరాశి అక్షరం *
dns_ఫలితం_totext(గుర్తులేని పూర్ణాంకం res)
{
	ఎంపిక (res) {
	స్థితి ERRSET_SUCCESS:
		తిరిగి errset_పాఠ్యం[ERRSET_SUCCESS];
	స్థితి ERRSET_NOMEMORY:
		తిరిగి errset_పాఠ్యం[ERRSET_NOMEMORY];
	స్థితి ERRSET_FAIL:
		తిరిగి errset_పాఠ్యం[ERRSET_FAIL];
	స్థితి ERRSET_INVAL:
		తిరిగి errset_పాఠ్యం[ERRSET_INVAL];
	స్థితి ERRSET_NONAME:
		తిరిగి errset_పాఠ్యం[ERRSET_NONAME];
	స్థితి ERRSET_NODATA:
		తిరిగి errset_పాఠ్యం[ERRSET_NODATA];
	అప్రమేయ:
		తిరిగి "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
స్థిర పూర్ణాంకం
dns_read_కీలకం(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, కొలత_t *digest_len, నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r, success = 0;
	పూర్ణాంకం fp_alg = -1;

	ఎంపిక (కీలకం->type) {
	స్థితి కీలకం_RSA:
		*algorithm = SSHFP_కీలకం_RSA;
		ఆపు;
	స్థితి కీలకం_ECDSA:
		*algorithm = SSHFP_కీలకం_ECDSA;
		ఆపు;
	స్థితి కీలకం_ED25519:
		*algorithm = SSHFP_కీలకం_ED25519;
		ఆపు;
	అప్రమేయ:
		*algorithm = SSHFP_కీలకం_RESERVED; /* 0 */
	}

	ఎంపిక (*digest_type) {
	స్థితి SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ఆపు;
	స్థితి SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ఆపు;
	అప్రమేయ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ఒకవేళ (*algorithm && *digest_type) {
		ఒకవేళ ((r = sshkey_fingerprint_raw(కీలకం, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} లేకపోతే {
		*digest = ఖాళీ;
		*digest_len = 0;
	}

	తిరిగి success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
స్థిర పూర్ణాంకం
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, కొలత_t *digest_len, u_char *rdata, పూర్ణాంకం rdata_len)
{
	పూర్ణాంకం success = 0;

	*algorithm = SSHFP_కీలకం_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ఒకవేళ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ఒకవేళ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			జ్ఞాపకం_నకలు(*digest, rdata + 2, *digest_len);
		} లేకపోతే {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	తిరిగి success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
స్థిర పూర్ణాంకం
is_numeric_hostname(స్థిరరాశి అక్షరం *hostname)
{
	నిర్మాణం addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ఒకవేళ (hostname == ఖాళీ) {
		error("is_numeric_hostname called with NULL hostname");
		తిరిగి -1;
	}

	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ఒకవేళ (getaddrinfo(hostname, ఖాళీ, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		తిరిగి -1;
	}

	తిరిగి 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
పూర్ణాంకం
verify_host_కీలకం_dns(స్థిరరాశి అక్షరం *hostname, నిర్మాణం sockaddr *చిరునామా,
    నిర్మాణం sshkey *hostkey, పూర్ణాంకం *flags)
{
	u_int counter;
	పూర్ణాంకం ఫలితం;
	నిర్మాణం rrsetinfo *fingerprints = ఖాళీ;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	కొలత_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	కొలత_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ఒకవేళ (hostkey == ఖాళీ)
		fatal("No key to look up!");

	ఒకవేళ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		తిరిగి -1;
	}

	ఫలితం = getrrsetbyname(hostname, DNS_RDATACLASS_లోపల,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ఒకవేళ (ఫలితం) {
		verbose("DNS lookup error: %s", dns_ఫలితం_totext(ఫలితం));
		తిరిగి -1;
	}

	ఒకవేళ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} లేకపోతే {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ఒకవేళ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_దొరికింది;

	కొరకు (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ఒకవేళ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_దత్తాంశం,
		    fingerprints->rri_rdatas[counter].rdi_నిడివి)) {
			verbose("Error parsing fingerprint from DNS.");
			కొనసాగు;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ఒకవేళ (!dns_read_కీలకం(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			విడుదల(dnskey_digest);
			freerrset(fingerprints);
			తిరిగి -1;
		}

		/* Check if the current key is the same as the given key */
		ఒకవేళ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ఒకవేళ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_సరిపోలిక;
			} లేకపోతే {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		విడుదల(dnskey_digest);
		విడుదల(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	ఒకవేళ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_సరిపోలిక;

	ఒకవేళ (*flags & DNS_VERIFY_దొరికింది)
		ఒకవేళ (*flags & DNS_VERIFY_సరిపోలిక)
			debug("matching host key fingerprint found in DNS");
		లేకపోతే
			debug("mismatching host key fingerprint found in DNS");
	లేకపోతే
		debug("no host key fingerprint found in DNS");

	తిరిగి 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
పూర్ణాంకం
export_dns_rr(స్థిరరాశి అక్షరం *hostname, నిర్మాణం sshkey *కీలకం, FILE *f, పూర్ణాంకం generic,
    పూర్ణాంకం alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	కొలత_t i, rdata_digest_len;
	పూర్ణాంకం success = 0;

	కొరకు (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ఒకవేళ (alg != -1 && dtype != alg)
			కొనసాగు;
		rdata_digest_type = dtype;
		ఒకవేళ (dns_read_కీలకం(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, కీలకం)) {
			ఒకవేళ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} లేకపోతే {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			కొరకు (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			విడుదల(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ఒకవేళ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	తిరిగి success;
}
