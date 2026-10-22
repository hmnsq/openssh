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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <netdb.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdlib.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "dns.h"
#समावेश "log.h"
#समावेश "digest.h"

अटल स्थिर अक्षर * स्थिर errset_text[] = {
	"success",		/* 0 ERRSET_SUCCESS */
	"out of memory",	/* 1 ERRSET_NOMEMORY */
	"general failure",	/* 2 ERRSET_FAIL */
	"invalid parameter",	/* 3 ERRSET_INVAL */
	"name does not exist",	/* 4 ERRSET_NONAME */
	"data does not exist",	/* 5 ERRSET_NODATA */
};

अटल स्थिर अक्षर *
dns_परिणाम_totext(अचिन्हित पूर्णांक res)
{
	चयन (res) {
	हाल ERRSET_SUCCESS:
		वापस errset_text[ERRSET_SUCCESS];
	हाल ERRSET_NOMEMORY:
		वापस errset_text[ERRSET_NOMEMORY];
	हाल ERRSET_FAIL:
		वापस errset_text[ERRSET_FAIL];
	हाल ERRSET_INVAL:
		वापस errset_text[ERRSET_INVAL];
	हाल ERRSET_NONAME:
		वापस errset_text[ERRSET_NONAME];
	हाल ERRSET_NODATA:
		वापस errset_text[ERRSET_NODATA];
	शेष:
		वापस "unknown error";
	}
}

/*
 * Read SSHFP parameters from key buffer.
 * Caller must free digest which is allocated by sshkey_fingerprint_raw().
 */
अटल पूर्णांक
dns_read_कुंजी(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, काष्ठा sshkey *कुंजी)
{
	पूर्णांक r, success = 0;
	पूर्णांक fp_alg = -1;

	चयन (कुंजी->type) {
	हाल कुंजी_RSA:
		*algorithm = SSHFP_कुंजी_RSA;
		अवरोध;
	हाल कुंजी_ECDSA:
		*algorithm = SSHFP_कुंजी_ECDSA;
		अवरोध;
	हाल कुंजी_ED25519:
		*algorithm = SSHFP_कुंजी_ED25519;
		अवरोध;
	शेष:
		*algorithm = SSHFP_कुंजी_RESERVED; /* 0 */
	}

	चयन (*digest_type) {
	हाल SSHFP_HASH_SHA1:
		fp_alg = SSH_DIGEST_SHA1;
		अवरोध;
	हाल SSHFP_HASH_SHA256:
		fp_alg = SSH_DIGEST_SHA256;
		अवरोध;
	शेष:
		*digest_type = SSHFP_HASH_RESERVED; /* 0 */
	}

	अगर (*algorithm && *digest_type) {
		अगर ((r = sshkey_fingerprint_raw(कुंजी, fp_alg, digest,
		    digest_len)) != 0)
			fatal_fr(r, "sshkey_fingerprint_raw");
		success = 1;
	} अन्यथा {
		*digest = शून्य;
		*digest_len = 0;
	}

	वापस success;
}

/*
 * Read SSHFP parameters from rdata buffer.
 */
अटल पूर्णांक
dns_read_rdata(uint8_t *algorithm, uint8_t *digest_type,
    u_char **digest, माप_प्रकार *digest_len, u_char *rdata, पूर्णांक rdata_len)
{
	पूर्णांक success = 0;

	*algorithm = SSHFP_कुंजी_RESERVED;
	*digest_type = SSHFP_HASH_RESERVED;

	अगर (rdata_len >= 2) {
		*algorithm = rdata[0];
		*digest_type = rdata[1];
		*digest_len = rdata_len - 2;

		अगर (*digest_len > 0) {
			*digest = xmalloc(*digest_len);
			स_नकल(*digest, rdata + 2, *digest_len);
		} अन्यथा {
			*digest = (u_char *)xstrdup("");
		}

		success = 1;
	}

	वापस success;
}

/*
 * Check if hostname is numerical.
 * Returns -1 if hostname is numeric, 0 otherwise
 */
अटल पूर्णांक
is_numeric_hostname(स्थिर अक्षर *hostname)
{
	काष्ठा addrinfo hints, *ai;

	/*
	 * We shouldn't ever get a null host but if we do then log an error
	 * and return -1 which stops DNS key fingerprint processing.
	 */
	अगर (hostname == शून्य) {
		error("is_numeric_hostname called with NULL hostname");
		वापस -1;
	}

	स_रखो(&hints, 0, माप(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	अगर (getaddrinfo(hostname, शून्य, &hints, &ai) == 0) {
		freeaddrinfo(ai);
		वापस -1;
	}

	वापस 0;
}

/*
 * Verify the given hostname, address and host key using DNS.
 * Returns 0 if lookup succeeds, -1 otherwise
 */
पूर्णांक
verify_host_कुंजी_dns(स्थिर अक्षर *hostname, काष्ठा sockaddr *address,
    काष्ठा sshkey *hostkey, पूर्णांक *flags)
{
	u_int गणक;
	पूर्णांक परिणाम;
	काष्ठा rrsetinfo *fingerprints = शून्य;

	uint8_t hostkey_algorithm;
	u_char *hostkey_digest;
	माप_प्रकार hostkey_digest_len;

	uint8_t dnskey_algorithm;
	uint8_t dnskey_digest_type;
	u_char *dnskey_digest;
	माप_प्रकार dnskey_digest_len;

	*flags = 0;

	debug3("verify_host_key_dns");
	अगर (hostkey == शून्य)
		fatal("No key to look up!");

	अगर (is_numeric_hostname(hostname)) {
		debug("skipped DNS lookup for numerical hostname");
		वापस -1;
	}

	परिणाम = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
	अगर (परिणाम) {
		verbose("DNS lookup error: %s", dns_परिणाम_totext(परिणाम));
		वापस -1;
	}

	अगर (fingerprints->rri_flags & RRSET_VALIDATED) {
		*flags |= DNS_VERIFY_SECURE;
		debug("found %d secure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	} अन्यथा {
		debug("found %d insecure fingerprints in DNS",
		    fingerprints->rri_nrdatas);
	}

	अगर (fingerprints->rri_nrdatas)
		*flags |= DNS_VERIFY_FOUND;

	क्रम (गणक = 0; गणक < fingerprints->rri_nrdatas; गणक++) {
		/*
		 * Extract the key from the answer. Ignore any badly
		 * formatted fingerprints.
		 */
		अगर (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
		    &dnskey_digest, &dnskey_digest_len,
		    fingerprints->rri_rdatas[गणक].rdi_तथ्य,
		    fingerprints->rri_rdatas[गणक].rdi_लंबाई)) {
			verbose("Error parsing fingerprint from DNS.");
			जारी;
		}
		debug3_f("checking SSHFP type %d fptype %d", dnskey_algorithm,
		    dnskey_digest_type);

		/* Calculate host key fingerprint. */
		अगर (!dns_read_कुंजी(&hostkey_algorithm, &dnskey_digest_type,
		    &hostkey_digest, &hostkey_digest_len, hostkey)) {
			error("Error calculating key fingerprint.");
			मुक्त(dnskey_digest);
			freerrset(fingerprints);
			वापस -1;
		}

		/* Check if the current key is the same as the given key */
		अगर (hostkey_algorithm == dnskey_algorithm &&
		    hostkey_digest_len == dnskey_digest_len) {
			अगर (timingsafe_bcmp(hostkey_digest, dnskey_digest,
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
	अगर (*flags & DNS_VERIFY_FAILED)
		*flags &= ~DNS_VERIFY_MATCH;

	अगर (*flags & DNS_VERIFY_FOUND)
		अगर (*flags & DNS_VERIFY_MATCH)
			debug("matching host key fingerprint found in DNS");
		अन्यथा
			debug("mismatching host key fingerprint found in DNS");
	अन्यथा
		debug("no host key fingerprint found in DNS");

	वापस 0;
}

/*
 * Export the fingerprint of a key as a DNS resource record
 */
पूर्णांक
export_dns_rr(स्थिर अक्षर *hostname, काष्ठा sshkey *कुंजी, खाता *f, पूर्णांक generic,
    पूर्णांक alg)
{
	uint8_t rdata_pubkey_algorithm = 0;
	uint8_t rdata_digest_type = SSHFP_HASH_RESERVED;
	uint8_t dtype;
	u_char *rdata_digest;
	माप_प्रकार i, rdata_digest_len;
	पूर्णांक success = 0;

	क्रम (dtype = SSHFP_HASH_SHA1; dtype < SSHFP_HASH_MAX; dtype++) {
		अगर (alg != -1 && dtype != alg)
			जारी;
		rdata_digest_type = dtype;
		अगर (dns_read_कुंजी(&rdata_pubkey_algorithm, &rdata_digest_type,
		    &rdata_digest, &rdata_digest_len, कुंजी)) {
			अगर (generic) {
				ख_लिखो(f, "%s IN TYPE%d \\# %zu %02x %02x ",
				    hostname, DNS_RDATATYPE_SSHFP,
				    2 + rdata_digest_len,
				    rdata_pubkey_algorithm, rdata_digest_type);
			} अन्यथा {
				ख_लिखो(f, "%s IN SSHFP %d %d ", hostname,
				    rdata_pubkey_algorithm, rdata_digest_type);
			}
			क्रम (i = 0; i < rdata_digest_len; i++)
				ख_लिखो(f, "%02x", rdata_digest[i]);
			ख_लिखो(f, "\n");
			मुक्त(rdata_digest); /* from sshkey_fingerprint_raw() */
			success = 1;
		}
	}

	/* No SSHFP record was generated at all */
	अगर (success == 0) {
		error_f("unsupported algorithm and/or digest_type");
	}

	वापस success;
}
