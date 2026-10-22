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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>

#ضمن <netdb.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "dns.h"
#ضمن "log.h"
#ضمن "digest.h"

ساكن ثابت حرف * ثابت errset_متن[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ساكن ثابت حرف *
dns_پایله_totext(بینښه صحيح res)
{
	بدل (res) {
	حالة ERRSET_SUCCESS:
		أرجع errset_متن[ERRSET_SUCCESS];
	حالة ERRSET_NOMEMORY:
		أرجع errset_متن[ERRSET_NOMEMORY];
	حالة ERRSET_FAIL:
		أرجع errset_متن[ERRSET_FAIL];
	حالة ERRSET_INVAL:
		أرجع errset_متن[ERRSET_INVAL];
	حالة ERRSET_NONAME:
		أرجع errset_متن[ERRSET_NONAME];
	حالة ERRSET_NODATA:
		أرجع errset_متن[ERRSET_NODATA];
	افتراضي:
		أرجع "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ساكن صحيح
dns_read_کلی(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, اندازه_t *digest_len, بنية sshkey *کلی)
{
	صحيح r, success = 0;
	صحيح fp_alg = -1;

	بدل (کلی->type) {
	حالة کلی_RSA:
		*algorithm = SSHFP_کلی_RSA;
		اكسر;
	حالة کلی_ECDSA:
		*algorithm = SSHFP_کلی_ECDSA;
		اكسر;
	حالة کلی_ED25519:
		*algorithm = SSHFP_کلی_ED25519;
		اكسر;
	افتراضي:
		*algorithm = SSHFP_کلی_RESERVED; /* 0 */
	}

	بدل (*digest_type) {
	حالة SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		اكسر;
	حالة SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		اكسر;
	افتراضي:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	إذا (*algorithm && *digest_type) {
		إذا ((r = sshkey_fingerprint_raw(کلی, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} وإلا {
		*digest = عدم;
		*digest_len = 0;
	}

	أرجع success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ساكن صحيح
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, اندازه_t *digest_len, u_char *rdata, صحيح rdata_len)
{
	صحيح success = 0;

	*algorithm = SSHFP_کلی_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	إذا (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		إذا (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			حافظه_نقل(*digest, rdata + 2, *digest_len);
		} وإلا {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	أرجع success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ساكن صحيح
is_numeric_hostname(ثابت حرف *hostname)
{
	بنية addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	إذا (hostname == عدم) {
		error("is_numeric_hostname called with NULL hostname");
		أرجع -1;
	}

	memset(&hints, 0, حجم(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	إذا (getaddrinfo(hostname, عدم, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		أرجع -1;
	}

	أرجع 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
صحيح
verify_host_کلی_dns(ثابت حرف *hostname, بنية sockaddr *پته,
    بنية sshkey *hostkey, صحيح *flags)
{
	u_int counter;
	صحيح پایله;
	بنية rrsetinfo *fingerprints = عدم;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	اندازه_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	اندازه_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	إذا (hostkey == عدم)
		fatal("No key to look up!");

	إذا (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		أرجع -1;
	}

	پایله = getrrsetbyname(hostname, DNS_RDATACLASS_دننه,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	إذا (پایله) {
		verbose("DNS lookup error: %s", dns_پایله_totext(پایله));
		أرجع -1;
	}

	إذا (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} وإلا {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	إذا (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_وموندل;

	لكل (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		إذا (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_معلومات,
		    fingerprints->rri_rdatas[counter].rdi_اوږدتیا)) {
			verbose("Error parsing fingerprint from DNS.");
			استمر;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		إذا (!dns_read_کلی(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			حرر(dnskey_digest);
			freerrset(fingerprints);
			أرجع -1;
		}

		/* Check if the current key is the same as the given key */
		إذا (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			إذا (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_سمون;
			} وإلا {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		حرر(dnskey_digest);
		حرر(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	إذا (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_سمون;

	إذا (*flags & DNS_VERIFY_وموندل)
		إذا (*flags & DNS_VERIFY_سمون)
			debug("matching host key fingerprint found in DNS");
		وإلا
			debug("mismatching host key fingerprint found in DNS");
	وإلا
		debug("no host key fingerprint found in DNS");

	أرجع 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
صحيح
export_dns_rr(ثابت حرف *hostname, بنية sshkey *کلی, FILE *f, صحيح generic,
    صحيح alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	اندازه_t i, rdata_digest_len;
	صحيح success = 0;

	لكل (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		إذا (alg != -1 && dtype != alg)
			استمر;
		rdata_digest_type = dtype;
		إذا (dns_read_کلی(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, کلی)) {
			إذا (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} وإلا {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			لكل (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			حرر(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	إذا (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	أرجع success;
}
