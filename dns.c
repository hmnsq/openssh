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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "dns.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "digest.h"

സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

സ്ഥിതം സ്ഥിരം അക്ഷരം *
dns_result_totext(unsigned പൂർണ്ണസംഖ്യ res)
{
	തിരഞ്ഞെടുപ്പ് (res) {
	അവസ്ഥ ERRSET_SUCCESS:
		തിരികെ errset_text[ERRSET_SUCCESS];
	അവസ്ഥ ERRSET_NOMEMORY:
		തിരികെ errset_text[ERRSET_NOMEMORY];
	അവസ്ഥ ERRSET_FAIL:
		തിരികെ errset_text[ERRSET_FAIL];
	അവസ്ഥ ERRSET_INVAL:
		തിരികെ errset_text[ERRSET_INVAL];
	അവസ്ഥ ERRSET_NONAME:
		തിരികെ errset_text[ERRSET_NONAME];
	അവസ്ഥ ERRSET_NODATA:
		തിരികെ errset_text[ERRSET_NODATA];
	സ്ഥിരസ്ഥിതി:
		തിരികെ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
dns_read_താക്കോൽ(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r, success = 0;
	പൂർണ്ണസംഖ്യ fp_alg = -1;

	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
	അവസ്ഥ താക്കോൽ_RSA:
		*algorithm = SSHFP_താക്കോൽ_RSA;
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		*algorithm = SSHFP_താക്കോൽ_ECDSA;
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ED25519:
		*algorithm = SSHFP_താക്കോൽ_ED25519;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		*algorithm = SSHFP_താക്കോൽ_RESERVED; /* 0 */
	}

	തിരഞ്ഞെടുപ്പ് (*digest_type) {
	അവസ്ഥ SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		നിർത്തുക;
	അവസ്ഥ SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	എങ്കിൽ (*algorithm && *digest_type) {
		എങ്കിൽ ((r = sshkey_fingerprint_raw(താക്കോൽ, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} അല്ലെങ്കിൽ {
		*digest = ശൂന്യ;
		*digest_len = 0;
	}

	തിരികെ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, size_t *digest_len, u_char *rdata, പൂർണ്ണസംഖ്യ rdata_len)
{
	പൂർണ്ണസംഖ്യ success = 0;

	*algorithm = SSHFP_താക്കോൽ_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	എങ്കിൽ (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		എങ്കിൽ (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			memcpy(*digest, rdata + 2, *digest_len);
		} അല്ലെങ്കിൽ {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	തിരികെ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_numeric_hostname(സ്ഥിരം അക്ഷരം *hostname)
{
	ഘടന addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	എങ്കിൽ (hostname == ശൂന്യ) {
		error("is_numeric_hostname called with NULL hostname");
		തിരികെ -1;
	}

	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	എങ്കിൽ (getaddrinfo(hostname, ശൂന്യ, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		തിരികെ -1;
	}

	തിരികെ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
പൂർണ്ണസംഖ്യ
verify_host_താക്കോൽ_dns(സ്ഥിരം അക്ഷരം *hostname, ഘടന sockaddr *address,
    ഘടന sshkey *hostkey, പൂർണ്ണസംഖ്യ *flags)
{
	u_int counter;
	പൂർണ്ണസംഖ്യ result;
	ഘടന rrsetinfo *fingerprints = ശൂന്യ;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	size_t hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	size_t dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	എങ്കിൽ (hostkey == ശൂന്യ)
		fatal("No key to look up!");

	എങ്കിൽ (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		തിരികെ -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	എങ്കിൽ (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		തിരികെ -1;
	}

	എങ്കിൽ (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} അല്ലെങ്കിൽ {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	എങ്കിൽ (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	വേണ്ടി (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		എങ്കിൽ (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			തുടരുക;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		എങ്കിൽ (!dns_read_താക്കോൽ(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			സ്വതന്ത്രം(dnskey_digest);
			freerrset(fingerprints);
			തിരികെ -1;
		}

		/* Check if the current key is the same as the given key */
		എങ്കിൽ (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			എങ്കിൽ (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} അല്ലെങ്കിൽ {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		സ്വതന്ത്രം(dnskey_digest);
		സ്വതന്ത്രം(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	എങ്കിൽ (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	എങ്കിൽ (*flags & DNS_VERIFY_FOUND)
		എങ്കിൽ (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		അല്ലെങ്കിൽ
			debug("mismatching host key fingerprint found in DNS");
	അല്ലെങ്കിൽ
		debug("no host key fingerprint found in DNS");

	തിരികെ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
പൂർണ്ണസംഖ്യ
export_dns_rr(സ്ഥിരം അക്ഷരം *hostname, ഘടന sshkey *താക്കോൽ, FILE *f, പൂർണ്ണസംഖ്യ generic,
    പൂർണ്ണസംഖ്യ alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	size_t i, rdata_digest_len;
	പൂർണ്ണസംഖ്യ success = 0;

	വേണ്ടി (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		എങ്കിൽ (alg != -1 && dtype != alg)
			തുടരുക;
		rdata_digest_type = dtype;
		എങ്കിൽ (dns_read_താക്കോൽ(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, താക്കോൽ)) {
			എങ്കിൽ (generic) {
				fprintf(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} അല്ലെങ്കിൽ {
				fprintf(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			വേണ്ടി (i = 0; i < rdata_digest_len; i++)
				fprintf(f, "%02x", rdata_digest[i]);
			fprintf(f, "\n");
			സ്വതന്ത്രം(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	എങ്കിൽ (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	തിരികെ success;
}
