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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dns.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ errset_ਪਾਠ[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
dns_ਨਤੀਜਾ_totext(ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ res)
{
	ਚੋਣ (res) {
	ਹਾਲਤ ERRSET_SUCCESS:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_SUCCESS];
	ਹਾਲਤ ERRSET_NOMEMORY:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_NOMEMORY];
	ਹਾਲਤ ERRSET_FAIL:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_FAIL];
	ਹਾਲਤ ERRSET_INVAL:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_INVAL];
	ਹਾਲਤ ERRSET_NONAME:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_NONAME];
	ਹਾਲਤ ERRSET_NODATA:
		ਵਾਪਸ errset_ਪਾਠ[ERRSET_NODATA];
	ਮੂਲ:
		ਵਾਪਸ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
ਸਥਿਰ ਪੂਰਨ
dns_read_ਕੁੰਜੀ(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, ਮਾਪ_t *digest_len, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r, success = 0;
	ਪੂਰਨ fp_alg = -1;

	ਚੋਣ (ਕੁੰਜੀ->type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		*algorithm = SSHFP_ਕੁੰਜੀ_RSA;
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		*algorithm = SSHFP_ਕੁੰਜੀ_ECDSA;
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		*algorithm = SSHFP_ਕੁੰਜੀ_ED25519;
		ਰੋਕੋ;
	ਮੂਲ:
		*algorithm = SSHFP_ਕੁੰਜੀ_RESERVED; /* 0 */
	}

	ਚੋਣ (*digest_type) {
	ਹਾਲਤ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		ਰੋਕੋ;
	ਹਾਲਤ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		ਰੋਕੋ;
	ਮੂਲ:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	ਜੇ (*algorithm && *digest_type) {
		ਜੇ ((r = sshkey_fingerprint_raw(ਕੁੰਜੀ, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} ਨਹੀਂਤਾਂ {
		*digest = ਨਿਰਾ;
		*digest_len = 0;
	}

	ਵਾਪਸ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
ਸਥਿਰ ਪੂਰਨ
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, ਮਾਪ_t *digest_len, u_char *rdata, ਪੂਰਨ rdata_len)
{
	ਪੂਰਨ success = 0;

	*algorithm = SSHFP_ਕੁੰਜੀ_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	ਜੇ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		ਜੇ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(*digest, rdata + 2, *digest_len);
		} ਨਹੀਂਤਾਂ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	ਵਾਪਸ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
ਸਥਿਰ ਪੂਰਨ
is_numeric_hostname(ਅਚਲ ਅੱਖਰ *hostname)
{
	ਬਣਤਰ addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	ਜੇ (hostname == ਨਿਰਾ) {
		error("is_numeric_hostname called with NULL hostname");
		ਵਾਪਸ -1;
	}

	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	ਜੇ (getaddrinfo(hostname, ਨਿਰਾ, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		ਵਾਪਸ -1;
	}

	ਵਾਪਸ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
ਪੂਰਨ
verify_host_ਕੁੰਜੀ_dns(ਅਚਲ ਅੱਖਰ *hostname, ਬਣਤਰ sockaddr *ਪਤਾ,
    ਬਣਤਰ sshkey *hostkey, ਪੂਰਨ *flags)
{
	u_int counter;
	ਪੂਰਨ ਨਤੀਜਾ;
	ਬਣਤਰ rrsetinfo *fingerprints = ਨਿਰਾ;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	ਮਾਪ_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	ਮਾਪ_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	ਜੇ (hostkey == ਨਿਰਾ)
		fatal("No key to look up!");

	ਜੇ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		ਵਾਪਸ -1;
	}

	ਨਤੀਜਾ = getrrsetbyname(hostname, DNS_RDATACLASS_ਵਿੱਚ,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	ਜੇ (ਨਤੀਜਾ) {
		verbose("DNS lookup error: %s", dns_ਨਤੀਜਾ_totext(ਨਤੀਜਾ));
		ਵਾਪਸ -1;
	}

	ਜੇ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} ਨਹੀਂਤਾਂ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	ਜੇ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_ਮਿਲਿਆ;

	ਲਈ (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		ਜੇ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_ਅੰਕੜੇ,
		    fingerprints->rri_rdatas[counter].rdi_ਲੰਮਾਈ)) {
			verbose("Error parsing fingerprint from DNS.");
			ਜਾਰੀ;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		ਜੇ (!dns_read_ਕੁੰਜੀ(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			ਮੁਕਤ(dnskey_digest);
			freerrset(fingerprints);
			ਵਾਪਸ -1;
		}

		/* Check if the current key is the same as the given key */
		ਜੇ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			ਜੇ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_ਮੇਲ;
			} ਨਹੀਂਤਾਂ {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		ਮੁਕਤ(dnskey_digest);
		ਮੁਕਤ(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	ਜੇ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_ਮੇਲ;

	ਜੇ (*flags & DNS_VERIFY_ਮਿਲਿਆ)
		ਜੇ (*flags & DNS_VERIFY_ਮੇਲ)
			debug("matching host key fingerprint found in DNS");
		ਨਹੀਂਤਾਂ
			debug("mismatching host key fingerprint found in DNS");
	ਨਹੀਂਤਾਂ
		debug("no host key fingerprint found in DNS");

	ਵਾਪਸ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
ਪੂਰਨ
export_dns_rr(ਅਚਲ ਅੱਖਰ *hostname, ਬਣਤਰ sshkey *ਕੁੰਜੀ, FILE *f, ਪੂਰਨ generic,
    ਪੂਰਨ alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	ਮਾਪ_t i, rdata_digest_len;
	ਪੂਰਨ success = 0;

	ਲਈ (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		ਜੇ (alg != -1 && dtype != alg)
			ਜਾਰੀ;
		rdata_digest_type = dtype;
		ਜੇ (dns_read_ਕੁੰਜੀ(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, ਕੁੰਜੀ)) {
			ਜੇ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} ਨਹੀਂਤਾਂ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			ਲਈ (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			ਮੁਕਤ(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	ਜੇ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	ਵਾਪਸ success;
}
