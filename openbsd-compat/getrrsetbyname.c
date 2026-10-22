/* $OpenBSD: getrrsetbyname.c,v 1.11 2007/10/11 18:36:41 jakob Exp $ */

/*
 * Copyright (c) 2001 Jakob Schlyter. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
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

/*
 * Portions Copyright (c) 1999-2001 Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/getrrsetbyname.c */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ "getrrsetbyname.h"

#ಆದರೆ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ h_errno;
#ಆದರೆ_ಅಂತ್ಯ

/* We don't need multithread support here */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ THREAD_ಖಾಸಗಿ
# undef THREAD_ಖಾಸಗಿ
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು THREAD_ಖಾಸಗಿ(a,b,c) (c)

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE__RES_EXTERN
ರಚನೆ __res_state _res;
#ಆದರೆ_ಅಂತ್ಯ

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INT32SZ
# define INT32SZ	4
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INT16SZ
# define INT16SZ	2
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ GETSHORT
#ವ್ಯಾಖ್ಯಾನಿಸು GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ GETLONG
#ವ್ಯಾಖ್ಯಾನಿಸು GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#ಆದರೆ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
    !defined(HAVE_DECL__GETSHORT) || HAVE_DECL__GETSHORT == 0 || \
    !defined(HAVE_DECL__GETLONG) || HAVE_DECL__GETLONG == 0
# ifdef _getshort
#  undef _getshort
# endif
# ifdef _getlong
#  undef _getlong
# endif
# define _getshort(x) (_ssh_compat_getshort(x))
# define _getlong(x) (_ssh_compat_getlong(x))
/*
 * Routines to insert/extract short/long's.
 */
ಸ್ಥಿರ u_int16_t
_getshort(ಸ್ಥಿರಾಂಕ u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ಹಿಂತಿರುಗಿ (u);
}

ಸ್ಥಿರ u_int32_t
_getlong(ಸ್ಥಿರಾಂಕ u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ಹಿಂತಿರುಗಿ (u);
}
#ಆದರೆ_ಅಂತ್ಯ /* missing _getshort/_getlong */

/* ************** */

#ವ್ಯಾಖ್ಯಾನಿಸು ANSWER_ಬಫರ್_ಗಾತ್ರ 0xffff

ರಚನೆ dns_query {
	ಅಕ್ಷರ			*name;
	u_int16_t		type;
	u_int16_t		class;
	ರಚನೆ dns_query	*ಮುಂದಿನ;
};

ರಚನೆ dns_rr {
	ಅಕ್ಷರ			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		ಗಾತ್ರ_2;
	ಶೂನ್ಯ			*rdata;
	ರಚನೆ dns_rr		*ಮುಂದಿನ;
};

ರಚನೆ dns_response {
	ಶೀರ್ಷಿಕೆ_2			ಶೀರ್ಷಿಕೆ_3;
	ರಚನೆ dns_query	*query;
	ರಚನೆ dns_rr		*answer;
	ರಚನೆ dns_rr		*authority;
	ರಚನೆ dns_rr		*additional;
};

ಸ್ಥಿರ ರಚನೆ dns_response *parse_dns_response(ಸ್ಥಿರಾಂಕ u_char *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ರಚನೆ dns_query *parse_dns_qsection(ಸ್ಥಿರಾಂಕ u_char *, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ u_char **, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ರಚನೆ dns_rr *parse_dns_rrsection(ಸ್ಥಿರಾಂಕ u_char *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ u_char **,
    ಪೂರ್ಣಾಂಕ);

ಸ್ಥಿರ ಶೂನ್ಯ free_dns_query(ರಚನೆ dns_query *);
ಸ್ಥಿರ ಶೂನ್ಯ free_dns_rr(ರಚನೆ dns_rr *);
ಸ್ಥಿರ ಶೂನ್ಯ free_dns_response(ರಚನೆ dns_response *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_dns_rr(ರಚನೆ dns_rr *, u_int16_t, u_int16_t);

ಪೂರ್ಣಾಂಕ
getrrsetbyname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ rdclass,
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ rdtype, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ flags,
    ರಚನೆ rrsetinfo **res)
{
	ರಚನೆ __res_state *_resp = THREAD_ಖಾಸಗಿ(_res, _res, &_res);
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ;
	ರಚನೆ rrsetinfo *rrset = ಖಾಲಿ;
	ರಚನೆ dns_response *response = ಖಾಲಿ;
	ರಚನೆ dns_rr *rr;
	ರಚನೆ rdatainfo *rdata;
	ಪೂರ್ಣಾಂಕ ಉದ್ದಳತೆ;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ ಸೂಚ್ಯಂಕ_ans, ಸೂಚ್ಯಂಕ_sig;
	u_char answer[ANSWER_ಬಫರ್_ಗಾತ್ರ];

	/* check for invalid class and type */
	ಆದರೆ (rdclass > 0xffff || rdtype > 0xffff) {
		ಫಲಿತಾಂಶ = ERRSET_INVAL;
		ಹೋಗು fail;
	}

	/* don't allow queries of class or type ANY */
	ಆದರೆ (rdclass == 0xff || rdtype == 0xff) {
		ಫಲಿತಾಂಶ = ERRSET_INVAL;
		ಹೋಗು fail;
	}

	/* don't allow flags yet, unimplemented */
	ಆದರೆ (flags) {
		ಫಲಿತಾಂಶ = ERRSET_INVAL;
		ಹೋಗು fail;
	}

	/* initialize resolver */
	ಆದರೆ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		ಫಲಿತಾಂಶ = ERRSET_FAIL;
		ಹೋಗು fail;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG
	_resp->options |= RES_DEBUG;
#ಆದರೆ_ಅಂತ್ಯ /* DEBUG */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ಆದರೆ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#ಆದರೆ_ಅಂತ್ಯ /* RES_USE_DNSEC */

	/* make query */
	ಉದ್ದಳತೆ = res_query(hostname, (ಚಿಹ್ನೆಯುಳ್ಳ ಪೂರ್ಣಾಂಕ) rdclass, (ಚಿಹ್ನೆಯುಳ್ಳ ಪೂರ್ಣಾಂಕ) rdtype,
	    answer, ಗಾತ್ರ(answer));
	ಆದರೆ (ಉದ್ದಳತೆ < 0) {
		ಆಯ್ಕೆ(h_errno) {
		ಸ್ಥಿತಿ HOST_NOT_FOUND:
			ಫಲಿತಾಂಶ = ERRSET_NONAME;
			ಹೋಗು fail;
		ಸ್ಥಿತಿ NO_DATA:
			ಫಲಿತಾಂಶ = ERRSET_NODATA;
			ಹೋಗು fail;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಫಲಿತಾಂಶ = ERRSET_FAIL;
			ಹೋಗು fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, ಉದ್ದಳತೆ);
	ಆದರೆ (response == ಖಾಲಿ) {
		ಫಲಿತಾಂಶ = ERRSET_FAIL;
		ಹೋಗು fail;
	}

	ಆದರೆ (response->ಶೀರ್ಷಿಕೆ_3.qdcount != 1) {
		ಫಲಿತಾಂಶ = ERRSET_FAIL;
		ಹೋಗು fail;
	}

	/* initialize rrset */
	rrset = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(ರಚನೆ rrsetinfo));
	ಆದರೆ (rrset == ಖಾಲಿ) {
		ಫಲಿತಾಂಶ = ERRSET_NOMEMORY;
		ಹೋಗು fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->ಶೀರ್ಷಿಕೆ_3.ancount;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಶೀರ್ಷಿಕೆ_AD
	/* check for authenticated data */
	ಆದರೆ (response->ಶೀರ್ಷಿಕೆ_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#ಆದರೆ_ಅಂತ್ಯ

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ಆದರೆ (rrset->rri_name == ಖಾಲಿ) {
		ಫಲಿತಾಂಶ = ERRSET_NOMEMORY;
		ಹೋಗು fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ಎಣಿಕೆ_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ಎಣಿಕೆ_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(rrset->rri_nrdatas,
	    ಗಾತ್ರ(ರಚನೆ rdatainfo));
	ಆದರೆ (rrset->rri_rdatas == ಖಾಲಿ) {
		ಫಲಿತಾಂಶ = ERRSET_NOMEMORY;
		ಹೋಗು fail;
	}

	/* allocate memory for signatures */
	ಆದರೆ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(rrset->rri_nsigs, ಗಾತ್ರ(ರಚನೆ rdatainfo));
		ಆದರೆ (rrset->rri_sigs == ಖಾಲಿ) {
			ಫಲಿತಾಂಶ = ERRSET_NOMEMORY;
			ಹೋಗು fail;
		}
	}

	/* copy answers & signatures */
	ಗಾಗಿ (rr = response->answer, ಸೂಚ್ಯಂಕ_ans = 0, ಸೂಚ್ಯಂಕ_sig = 0;
	    rr; rr = rr->ಮುಂದಿನ) {

		rdata = ಖಾಲಿ;

		ಆದರೆ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[ಸೂಚ್ಯಂಕ_ans++];

		ಆದರೆ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[ಸೂಚ್ಯಂಕ_sig++];

		ಆದರೆ (rdata) {
			rdata->rdi_ಉದ್ದಳತೆ = rr->ಗಾತ್ರ_2;
			ಆದರೆ (rr->ಗಾತ್ರ_2 != 0) {
				rdata->rdi_ದತ್ತಾಂಶ   = ಸ್ಮರಣೆ_ಕೊಡು(rr->ಗಾತ್ರ_2);
				ಆದರೆ (rdata->rdi_ದತ್ತಾಂಶ == ಖಾಲಿ) {
					ಫಲಿತಾಂಶ = ERRSET_NOMEMORY;
					ಹೋಗು fail;
				}
				ಸ್ಮರಣೆ_ನಕಲು(rdata->rdi_ದತ್ತಾಂಶ, rr->rdata, rr->ಗಾತ್ರ_2);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ಹಿಂತಿರುಗಿ (ERRSET_SUCCESS);

fail:
	ಆದರೆ (rrset != ಖಾಲಿ)
		freerrset(rrset);
	ಆದರೆ (response != ಖಾಲಿ)
		free_dns_response(response);
	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ);
}

ಶೂನ್ಯ
freerrset(ರಚನೆ rrsetinfo *rrset)
{
	u_int16_t i;

	ಆದರೆ (rrset == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (rrset->rri_rdatas) {
		ಗಾಗಿ (i = 0; i < rrset->rri_nrdatas; i++) {
			ಆದರೆ (rrset->rri_rdatas[i].rdi_ದತ್ತಾಂಶ == ಖಾಲಿ)
				ನಿಲ್ಲಿಸು;
			ಬಿಡುಗಡೆ(rrset->rri_rdatas[i].rdi_ದತ್ತಾಂಶ);
		}
		ಬಿಡುಗಡೆ(rrset->rri_rdatas);
	}

	ಆದರೆ (rrset->rri_sigs) {
		ಗಾಗಿ (i = 0; i < rrset->rri_nsigs; i++) {
			ಆದರೆ (rrset->rri_sigs[i].rdi_ದತ್ತಾಂಶ == ಖಾಲಿ)
				ನಿಲ್ಲಿಸು;
			ಬಿಡುಗಡೆ(rrset->rri_sigs[i].rdi_ದತ್ತಾಂಶ);
		}
		ಬಿಡುಗಡೆ(rrset->rri_sigs);
	}

	ಆದರೆ (rrset->rri_name)
		ಬಿಡುಗಡೆ(rrset->rri_name);
	ಬಿಡುಗಡೆ(rrset);
}

/*
 * DNS response parsing routines
 */
ಸ್ಥಿರ ರಚನೆ dns_response *
parse_dns_response(ಸ್ಥಿರಾಂಕ u_char *answer, ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_2)
{
	ರಚನೆ dns_response *resp;
	ಸ್ಥಿರಾಂಕ u_char *cp;

	ಆದರೆ (ಗಾತ್ರ_2 < HFIXEDSZ)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

	/* allocate memory for the response */
	resp = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*resp));
	ಆದರೆ (resp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	ಸ್ಮರಣೆ_ನಕಲು(&resp->ಶೀರ್ಷಿಕೆ_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->ಶೀರ್ಷಿಕೆ_3.qdcount = ntohs(resp->ಶೀರ್ಷಿಕೆ_3.qdcount);
	resp->ಶೀರ್ಷಿಕೆ_3.ancount = ntohs(resp->ಶೀರ್ಷಿಕೆ_3.ancount);
	resp->ಶೀರ್ಷಿಕೆ_3.nscount = ntohs(resp->ಶೀರ್ಷಿಕೆ_3.nscount);
	resp->ಶೀರ್ಷಿಕೆ_3.arcount = ntohs(resp->ಶೀರ್ಷಿಕೆ_3.arcount);

	/* there must be at least one query */
	ಆದರೆ (resp->ಶೀರ್ಷಿಕೆ_3.qdcount < 1) {
		free_dns_response(resp);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, ಗಾತ್ರ_2, &cp,
	    resp->ಶೀರ್ಷಿಕೆ_3.qdcount);
	ಆದರೆ (resp->ಶೀರ್ಷಿಕೆ_3.qdcount && resp->query == ಖಾಲಿ) {
		free_dns_response(resp);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, ಗಾತ್ರ_2, &cp,
	    resp->ಶೀರ್ಷಿಕೆ_3.ancount);
	ಆದರೆ (resp->ಶೀರ್ಷಿಕೆ_3.ancount && resp->answer == ಖಾಲಿ) {
		free_dns_response(resp);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, ಗಾತ್ರ_2, &cp,
	    resp->ಶೀರ್ಷಿಕೆ_3.nscount);
	ಆದರೆ (resp->ಶೀರ್ಷಿಕೆ_3.nscount && resp->authority == ಖಾಲಿ) {
		free_dns_response(resp);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, ಗಾತ್ರ_2, &cp,
	    resp->ಶೀರ್ಷಿಕೆ_3.arcount);
	ಆದರೆ (resp->ಶೀರ್ಷಿಕೆ_3.arcount && resp->additional == ಖಾಲಿ) {
		free_dns_response(resp);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	ಹಿಂತಿರುಗಿ (resp);
}

ಸ್ಥಿರ ರಚನೆ dns_query *
parse_dns_qsection(ಸ್ಥಿರಾಂಕ u_char *answer, ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_2, ಸ್ಥಿರಾಂಕ u_char **cp, ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2)
{
	ರಚನೆ dns_query *ತಲೆ, *curr, *prev;
	ಪೂರ್ಣಾಂಕ i, ಉದ್ದಳತೆ;
	ಅಕ್ಷರ name[MAXDNAME];

#ವ್ಯಾಖ್ಯಾನಿಸು NEED(need) \
	ಮಾಡು { \
		ಆದರೆ (*cp + need > answer + ಗಾತ್ರ_2) \
			ಹೋಗು fail; \
	} ಆಗ (0)

	ಗಾಗಿ (i = 1, ತಲೆ = ಖಾಲಿ, prev = ಖಾಲಿ; i <= ಎಣಿಕೆ_2; i++, prev = curr) {
		ಆದರೆ (*cp >= answer + ಗಾತ್ರ_2) {
 fail:
			free_dns_query(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		/* allocate and initialize struct */
		curr = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(ರಚನೆ dns_query));
		ಆದರೆ (curr == ಖಾಲಿ)
			ಹೋಗು fail;
		ಆದರೆ (ತಲೆ == ಖಾಲಿ)
			ತಲೆ = curr;
		ಆದರೆ (prev != ಖಾಲಿ)
			prev->ಮುಂದಿನ = curr;

		/* name */
		ಉದ್ದಳತೆ = dn_expand(answer, answer + ಗಾತ್ರ_2, *cp, name,
		    ಗಾತ್ರ(name));
		ಆದರೆ (ಉದ್ದಳತೆ < 0) {
			free_dns_query(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		curr->name = strdup(name);
		ಆದರೆ (curr->name == ಖಾಲಿ) {
			free_dns_query(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		NEED(ಉದ್ದಳತೆ);
		*cp += ಉದ್ದಳತೆ;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು NEED

	ಹಿಂತಿರುಗಿ (ತಲೆ);
}

ಸ್ಥಿರ ರಚನೆ dns_rr *
parse_dns_rrsection(ಸ್ಥಿರಾಂಕ u_char *answer, ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_2, ಸ್ಥಿರಾಂಕ u_char **cp,
    ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2)
{
	ರಚನೆ dns_rr *ತಲೆ, *curr, *prev;
	ಪೂರ್ಣಾಂಕ i, ಉದ್ದಳತೆ;
	ಅಕ್ಷರ name[MAXDNAME];

#ವ್ಯಾಖ್ಯಾನಿಸು NEED(need) \
	ಮಾಡು { \
		ಆದರೆ (*cp + need > answer + ಗಾತ್ರ_2) \
			ಹೋಗು fail; \
	} ಆಗ (0)

	ಗಾಗಿ (i = 1, ತಲೆ = ಖಾಲಿ, prev = ಖಾಲಿ; i <= ಎಣಿಕೆ_2; i++, prev = curr) {
		ಆದರೆ (*cp >= answer + ಗಾತ್ರ_2) {
 fail:
			free_dns_rr(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}

		/* allocate and initialize struct */
		curr = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(ರಚನೆ dns_rr));
		ಆದರೆ (curr == ಖಾಲಿ)
			ಹೋಗು fail;
		ಆದರೆ (ತಲೆ == ಖಾಲಿ)
			ತಲೆ = curr;
		ಆದರೆ (prev != ಖಾಲಿ)
			prev->ಮುಂದಿನ = curr;

		/* name */
		ಉದ್ದಳತೆ = dn_expand(answer, answer + ಗಾತ್ರ_2, *cp, name,
		    ಗಾತ್ರ(name));
		ಆದರೆ (ಉದ್ದಳತೆ < 0) {
			free_dns_rr(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		curr->name = strdup(name);
		ಆದರೆ (curr->name == ಖಾಲಿ) {
			free_dns_rr(ತಲೆ);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		NEED(ಉದ್ದಳತೆ);
		*cp += ಉದ್ದಳತೆ;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;

		/* ttl */
		NEED(INT32SZ);
		curr->ttl = _getlong(*cp);
		*cp += INT32SZ;

		/* rdata size */
		NEED(INT16SZ);
		curr->ಗಾತ್ರ_2 = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->ಗಾತ್ರ_2);
		ಆದರೆ (curr->ಗಾತ್ರ_2 != 0) {
			ಆದರೆ ((curr->rdata = ಸ್ಮರಣೆ_ಕೊಡು(curr->ಗಾತ್ರ_2)) == ಖಾಲಿ) {
				free_dns_rr(ತಲೆ);
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			}
			ಸ್ಮರಣೆ_ನಕಲು(curr->rdata, *cp, curr->ಗಾತ್ರ_2);
		}
		*cp += curr->ಗಾತ್ರ_2;
	}
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು NEED

	ಹಿಂತಿರುಗಿ (ತಲೆ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_query(ರಚನೆ dns_query *p)
{
	ರಚನೆ dns_query *ಮುಂದಿನ;

	ಆಗ (p != ಖಾಲಿ) {
		ಮುಂದಿನ = p->ಮುಂದಿನ;
		ಬಿಡುಗಡೆ(p->name);
		ಬಿಡುಗಡೆ(p);
		p = ಮುಂದಿನ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_rr(ರಚನೆ dns_rr *p)
{
	ರಚನೆ dns_rr *ಮುಂದಿನ;

	ಆಗ (p != ಖಾಲಿ) {
		ಮುಂದಿನ = p->ಮುಂದಿನ;
		ಬಿಡುಗಡೆ(p->name);
		ಬಿಡುಗಡೆ(p->rdata);
		ಬಿಡುಗಡೆ(p);
		p = ಮುಂದಿನ;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_response(ರಚನೆ dns_response *p)
{
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	ಬಿಡುಗಡೆ(p);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಎಣಿಕೆ_dns_rr(ರಚನೆ dns_rr *p, u_int16_t class, u_int16_t type)
{
	ಪೂರ್ಣಾಂಕ n = 0;

	ಆಗ(p) {
		ಆದರೆ (p->class == class && p->type == type)
			n++;
		p = p->ಮುಂದಿನ;
	}

	ಹಿಂತಿರುಗಿ (n);
}

#ಆದರೆ_ಅಂತ್ಯ /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
