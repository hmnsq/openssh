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

स्थिर स्थिरांक अक्षर * स्थिरांक errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

स्थिर स्थिरांक अक्षर *
dns_result_totext(अचिन्हित पूर्णांक res)
{
	निवड (res) {
	स्थिती ERRSET_SUCCESS:
		परत errset_text[ERRSET_SUCCESS];
	स्थिती ERRSET_NOMEMORY:
		परत errset_text[ERRSET_NOMEMORY];
	स्थिती ERRSET_FAIL:
		परत errset_text[ERRSET_FAIL];
	स्थिती ERRSET_INVAL:
		परत errset_text[ERRSET_INVAL];
	स्थिती ERRSET_NONAME:
		परत errset_text[ERRSET_NONAME];
	स्थिती ERRSET_NODATA:
		परत errset_text[ERRSET_NODATA];
	पूर्वनिर्धारित:
		परत "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
स्थिर पूर्णांक
dns_read_किल्ली(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, संरचना sshkey *किल्ली)
{
	पूर्णांक r, success = 0;
	पूर्णांक fp_alg = -1;

	निवड (किल्ली->type) {
	स्थिती किल्ली_RSA:
		*algorithm = SSHFP_किल्ली_RSA;
		थांबा;
	स्थिती किल्ली_ECDSA:
		*algorithm = SSHFP_किल्ली_ECDSA;
		थांबा;
	स्थिती किल्ली_ED25519:
		*algorithm = SSHFP_किल्ली_ED25519;
		थांबा;
	पूर्वनिर्धारित:
		*algorithm = SSHFP_किल्ली_RESERVED; /* 0 */
	}

	निवड (*digest_type) {
	स्थिती SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		थांबा;
	स्थिती SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		थांबा;
	पूर्वनिर्धारित:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	जर (*algorithm && *digest_type) {
		जर ((r = sshkey_fingerprint_raw(किल्ली, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} अन्यथा {
		*digest = रिक्त;
		*digest_len = 0;
	}

	परत success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
स्थिर पूर्णांक
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, u_char *rdata, पूर्णांक rdata_len)
{
	पूर्णांक success = 0;

	*algorithm = SSHFP_किल्ली_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	जर (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		जर (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			स_नकल(*digest, rdata + 2, *digest_len);
		} अन्यथा {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	परत success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
स्थिर पूर्णांक
is_numeric_hostname(स्थिरांक अक्षर *hostname)
{
	संरचना addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	जर (hostname == रिक्त) {
		error("is_numeric_hostname called with NULL hostname");
		परत -1;
	}

	स_रखो(&hints, 0, आकार(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	जर (getaddrinfo(hostname, रिक्त, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		परत -1;
	}

	परत 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
पूर्णांक
verify_host_किल्ली_dns(स्थिरांक अक्षर *hostname, संरचना sockaddr *address,
    संरचना sshkey *hostkey, पूर्णांक *flags)
{
	u_int counter;
	पूर्णांक result;
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
	जर (hostkey == रिक्त)
		fatal("No key to look up!");

	जर (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		परत -1;
	}

	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	जर (result) {
		verbose("DNS lookup error: %s", dns_result_totext(result));
		परत -1;
	}

	जर (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} अन्यथा {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	जर (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	साठी (counter = 0; counter < fingerprints->rri_nrdatas; counter++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		जर (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[counter].rdi_data,
		    fingerprints->rri_rdatas[counter].rdi_length)) {
			verbose("Error parsing fingerprint from DNS.");
			सुरूठेवा;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		जर (!dns_read_किल्ली(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			मुक्त(dnskey_digest);
			freerrset(fingerprints);
			परत -1;
		}

		/* Check if the current key is the same as the given key */
		जर (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			जर (timingsafe_bcmp(hostkey_digest, dnskey_digest,
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
	जर (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	जर (*flags & DNS_VERIFY_FOUND)
		जर (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		अन्यथा
			debug("mismatching host key fingerprint found in DNS");
	अन्यथा
		debug("no host key fingerprint found in DNS");

	परत 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
पूर्णांक
export_dns_rr(स्थिरांक अक्षर *hostname, संरचना sshkey *किल्ली, खाता *f, पूर्णांक generic,
    पूर्णांक alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	माप_प्रकार i, rdata_digest_len;
	पूर्णांक success = 0;

	साठी (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		जर (alg != -1 && dtype != alg)
			सुरूठेवा;
		rdata_digest_type = dtype;
		जर (dns_read_किल्ली(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, किल्ली)) {
			जर (generic) {
				ख_लिखो(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} अन्यथा {
				ख_लिखो(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			साठी (i = 0; i < rdata_digest_len; i++)
				ख_लिखो(f, "%02x", rdata_digest[i]);
			ख_लिखो(f, "\n");
			मुक्त(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	जर (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	परत success;
}
