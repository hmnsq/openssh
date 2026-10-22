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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>

#شامل <netdb.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "dns.h"
#شامل "log.h"
#شامل "digest.h"

ساکن ثابت حرف * ثابت errset_متن[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ساکن ثابت حرف *
dns_نتیجہ_totext(غیرعلامتی صحیح res)
{
	انتخاب (res) {
	حالت ERRSET_SUCCESS:
		واپس errset_متن[ERRSET_SUCCESS];
	حالت ERRSET_NOMEMORY:
		واپس errset_متن[ERRSET_NOMEMORY];
	حالت ERRSET_FAIL:
		واپس errset_متن[ERRSET_FAIL];
	حالت ERRSET_INVAL:
		واپس errset_متن[ERRSET_INVAL];
	حالت ERRSET_NONAME:
		واپس errset_متن[ERRSET_NONAME];
	حالت ERRSET_NODATA:
		واپس errset_متن[ERRSET_NODATA];
	طےشدہ:
		واپس "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ساکن صحیح
dns_read_کلید(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, سائز_t *digest_len, ساخت sshkey *کلید)
{
	صحیح r, success = 0;
	صحیح fp_alg = -1;

	انتخاب (کلید->type) {
	حالت کلید_RSA:
		*algorithm = SSHFP_کلید_RSA;
		توڑو;
	حالت کلید_ECDSA:
		*algorithm = SSHFP_کلید_ECDSA;
		توڑو;
	حالت کلید_ED25519:
		*algorithm = SSHFP_کلید_ED25519;
		توڑو;
	طےشدہ:
		*algorithm = SSHFP_کلید_RESERVED; /* 0 */
	}

	انتخاب (*digest_type) {
	حالت SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		توڑو;
	حالت SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		توڑو;
	طےشدہ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	اگر (*algorithm && *digest_type) {
		اگر ((r = sshkey_fingerprint_raw(کلید, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ورنہ {
		*digest = تہی;
		*digest_len = 0;
	}

	واپس success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ساکن صحیح
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, سائز_t *digest_len, u_char *rdata, صحیح rdata_len)
{
	صحیح success = 0;

	*algorithm = SSHFP_کلید_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	اگر (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		اگر (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			حافظہ_نقل(*digest, rdata + 2, *digest_len);
		} ورنہ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	واپس success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ساکن صحیح
is_numeric_hostname(ثابت حرف *hostname)
{
	ساخت addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	اگر (hostname == تہی) {
		error("is_numeric_hostname called with NULL hostname");
		واپس -1;
	}

	memset(&hints, 0, حجم(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	اگر (getaddrinfo(hostname, تہی, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		واپس -1;
	}

	واپس 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
صحیح
verify_host_کلید_dns(ثابت حرف *hostname, ساخت sockaddr *پتہ,
    ساخت sshkey *hostkey, صحیح *flags)
{
	u_int شمار_2;
	صحیح نتیجہ;
	ساخت rrsetinfo *fingerprints = تہی;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	سائز_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	سائز_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	اگر (hostkey == تہی)
		fatal("No key to look up!");

	اگر (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		واپس -1;
	}

	نتیجہ = getrrsetbyname(hostname, DNS_RDATACLASS_اندر,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	اگر (نتیجہ) {
		verbose("DNS lookup error: %s", dns_نتیجہ_totext(نتیجہ));
		واپس -1;
	}

	اگر (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ورنہ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	اگر (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_ملا;

	برائے (شمار_2 = 0; شمار_2 < fingerprints->rri_nrdatas; شمار_2++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		اگر (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[شمار_2].rdi_ڈیٹا,
		    fingerprints->rri_rdatas[شمار_2].rdi_لمبائی)) {
			verbose("Error parsing fingerprint from DNS.");
			جاری;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		اگر (!dns_read_کلید(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			آزاد(dnskey_digest);
			freerrset(fingerprints);
			واپس -1;
		}

		/* Check if the current key is the same as the given key */
		اگر (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			اگر (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_مطابقت;
			} ورنہ {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		آزاد(dnskey_digest);
		آزاد(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	اگر (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_مطابقت;

	اگر (*flags & DNS_VERIFY_ملا)
		اگر (*flags & DNS_VERIFY_مطابقت)
			debug("matching host key fingerprint found in DNS");
		ورنہ
			debug("mismatching host key fingerprint found in DNS");
	ورنہ
		debug("no host key fingerprint found in DNS");

	واپس 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
صحیح
export_dns_rr(ثابت حرف *hostname, ساخت sshkey *کلید, FILE *f, صحیح generic,
    صحیح alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	سائز_t i, rdata_digest_len;
	صحیح success = 0;

	برائے (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		اگر (alg != -1 && dtype != alg)
			جاری;
		rdata_digest_type = dtype;
		اگر (dns_read_کلید(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, کلید)) {
			اگر (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ورنہ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			برائے (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			آزاد(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	اگر (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	واپس success;
}
