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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "digest.h"

स्थिर अचर वर्ण * अचर errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

स्थिर अचर वर्ण *
dns_result_totext(अचिन्हित पूर्णाङ्क res)
{
	विकल्प (res) {
	पक्ष ERRSET_SUCCESS:
		फर्काऊ errset_text[ERRSET_SUCCESS];
	पक्ष ERRSET_NOMEMORY:
		फर्काऊ errset_text[ERRSET_NOMEMORY];
	पक्ष ERRSET_FAIL:
		फर्काऊ errset_text[ERRSET_FAIL];
	पक्ष ERRSET_INVAL:
		फर्काऊ errset_text[ERRSET_INVAL];
	पक्ष ERRSET_NONAME:
		फर्काऊ errset_text[ERRSET_NONAME];
	पक्ष ERRSET_NODATA:
		फर्काऊ errset_text[ERRSET_NODATA];
	स्वभाव:
		फर्काऊ "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
स्थिर पूर्णाङ्क
dns_read_साँचो(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, संरचना sshkey *साँचो)
{
	पूर्णाङ्क r, success = 0;
	पूर्णाङ्क fp_alg = -1;

	विकल्प (साँचो->type) {
	पक्ष साँचो_RSA:
		*algorithm = SSHFP_साँचो_RSA;
		रोक;
	पक्ष साँचो_ECDSA:
		*algorithm = SSHFP_साँचो_ECDSA;
		रोक;
	पक्ष साँचो_ED25519:
		*algorithm = SSHFP_साँचो_ED25519;
		रोक;
	स्वभाव:
		*algorithm = SSHFP_साँचो_RESERVED; /* 0 */
	}

	विकल्प (*digest_type) {
	पक्ष SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		रोक;
	पक्ष SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		रोक;
	स्वभाव:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	यदि (*algorithm && *digest_type) {
		यदि ((r = sshkey_fingerprint_raw(साँचो, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} अन्यथा {
		*digest = रिक्त;
		*digest_len = 0;
	}

	फर्काऊ success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
स्थिर पूर्णाङ्क
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, u_char *rdata, पूर्णाङ्क rdata_len)
{
	पूर्णाङ्क success = 0;

	*algorithm = SSHFP_साँचो_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	यदि (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		यदि (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			स_नकल(*digest, rdata + 2, *digest_len);
		} अन्यथा {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	फर्काऊ success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
स्थिर पूर्णाङ्क
is_numeric_hostname(अचर वर्ण *hostname)
{
	संरचना addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	यदि (hostname == रिक्त) {
		error("is_numeric_hostname called with NULL hostname");
		फर्काऊ -1;
	}

	स_रखो(&hints, 0, परिमाण(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	यदि (getaddrinfo(hostname, रिक्त, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		फर्काऊ -1;
	}

	फर्काऊ 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
पूर्णाङ्क
verify_host_साँचो_dns(अचर वर्ण *hostname, संरचना sockaddr *address,
    संरचना sshkey *hostkey, पूर्णाङ्क *flags)
{
	u_int counter;
	पूर्णाङ्क result;
	संरचना rrsetinfo *fingerprints = रिक्त;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	माप_प्रकार hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	माप_प्रकार dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	यदि (hostkey == रिक्त)
		fatal("No key to look up!");

	यदि (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		फर्काऊ -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	यदि (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		फर्काऊ -1;
	}

	यदि (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} अन्यथा {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	यदि (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	लागि (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		यदि (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			जारी;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		यदि (!dns_read_साँचो(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			मुक्त(dnskey_digest);
			freerrset(fingerprints);
			फर्काऊ -1;
		}

		/* Check if the current key is the same as the given key */
		यदि (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			यदि (timingsafe_bcmp(hostkey_digest, dnskey_digest,
			    hostkey_digest_len) == 0) {
				debug_f("matched SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_MATCH;
			} अन्यथा {
				debug_f("failed SSHFP type %d fptype %d",
				    dnskey_algorithm, dnskey_digest_type);
				*flags |= DNS_VERIFY_FAILED;
			}
		}
		मुक्त(dnskey_digest);
		मुक्त(hostkey_digest); /* from sshkey_fingerprint_raw() */
	}

	freerrset(fingerprints);

	/* If any fingerprint failed to validate, return failure. */
	यदि (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	यदि (*flags & DNS_VERIFY_FOUND)
		यदि (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		अन्यथा
			debug("mismatching host key fingerprint found in DNS");
	अन्यथा
		debug("no host key fingerprint found in DNS");

	फर्काऊ 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
पूर्णाङ्क
export_dns_rr(अचर वर्ण *hostname, संरचना sshkey *साँचो, खाता *f, पूर्णाङ्क generic,
    पूर्णाङ्क alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	माप_प्रकार i, rdata_digest_len;
	पूर्णाङ्क success = 0;

	लागि (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		यदि (alg != -1 && dtype != alg)
			जारी;
		rdata_digest_type = dtype;
		यदि (dns_read_साँचो(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, साँचो)) {
			यदि (generic) {
				ख_लिखो(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} अन्यथा {
				ख_लिखो(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			लागि (i = 0; i < rdata_digest_len; i++)
				ख_लिखो(f, "%02x", rdata_digest[i]);
			ख_लिखो(f, "\n");
			मुक्त(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	यदि (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	फर्काऊ success;
}
