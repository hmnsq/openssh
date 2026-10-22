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

#অন্তর্ভাব "includes.h"

#যদি !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব "getrrsetbyname.h"

#যদি defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
বাহ্যিক পূর্ণসংখ্যা h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
কাঠামো __res_state _res;
#endif

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#ifndef INT32SZ
# define INT32SZ	4
#endif
#ifndef INT16SZ
# define INT16SZ	2
#endif

#ifndef GETSHORT
#define GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#endif

#ifndef GETLONG
#define GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#endif

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#যদি !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
স্থির u_int16_t
_getshort(ধ্রুবক u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ফেরত (u);
}

স্থির u_int32_t
_getlong(ধ্রুবক u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ফেরত (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_বাফার_আকার 0xffff

কাঠামো dns_query {
	অক্ষর			*name;
	u_int16_t		type;
	u_int16_t		class;
	কাঠামো dns_query	*পরবর্তী;
};

কাঠামো dns_rr {
	অক্ষর			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		আকার_2;
	শূন্য			*rdata;
	কাঠামো dns_rr		*পরবর্তী;
};

কাঠামো dns_response {
	HEADER			header;
	কাঠামো dns_query	*query;
	কাঠামো dns_rr		*answer;
	কাঠামো dns_rr		*authority;
	কাঠামো dns_rr		*additional;
};

স্থির কাঠামো dns_response *parse_dns_response(ধ্রুবক u_char *, পূর্ণসংখ্যা);
স্থির কাঠামো dns_query *parse_dns_qsection(ধ্রুবক u_char *, পূর্ণসংখ্যা,
    ধ্রুবক u_char **, পূর্ণসংখ্যা);
স্থির কাঠামো dns_rr *parse_dns_rrsection(ধ্রুবক u_char *, পূর্ণসংখ্যা, ধ্রুবক u_char **,
    পূর্ণসংখ্যা);

স্থির শূন্য free_dns_query(কাঠামো dns_query *);
স্থির শূন্য free_dns_rr(কাঠামো dns_rr *);
স্থির শূন্য free_dns_response(কাঠামো dns_response *);

স্থির পূর্ণসংখ্যা গুনতি_dns_rr(কাঠামো dns_rr *, u_int16_t, u_int16_t);

পূর্ণসংখ্যা
getrrsetbyname(ধ্রুবক অক্ষর *hostname, unsigned পূর্ণসংখ্যা rdclass,
    unsigned পূর্ণসংখ্যা rdtype, unsigned পূর্ণসংখ্যা flags,
    কাঠামো rrsetinfo **res)
{
	কাঠামো __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	পূর্ণসংখ্যা ফলাফল;
	কাঠামো rrsetinfo *rrset = ফাঁকা;
	কাঠামো dns_response *response = ফাঁকা;
	কাঠামো dns_rr *rr;
	কাঠামো rdatainfo *rdata;
	পূর্ণসংখ্যা দৈর্ঘ্য;
	unsigned পূর্ণসংখ্যা সূচক_ans, সূচক_sig;
	u_char answer[ANSWER_বাফার_আকার];

	/* check for invalid class and type */
	যদি (rdclass > 0xffff || rdtype > 0xffff) {
		ফলাফল = ERRSET_INVAL;
		যাও fail;
	}

	/* don't allow queries of class or type ANY */
	যদি (rdclass == 0xff || rdtype == 0xff) {
		ফলাফল = ERRSET_INVAL;
		যাও fail;
	}

	/* don't allow flags yet, unimplemented */
	যদি (flags) {
		ফলাফল = ERRSET_INVAL;
		যাও fail;
	}

	/* initialize resolver */
	যদি ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		ফলাফল = ERRSET_FAIL;
		যাও fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	যদি (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	দৈর্ঘ্য = res_query(hostname, (signed পূর্ণসংখ্যা) rdclass, (signed পূর্ণসংখ্যা) rdtype,
	    answer, আকার(answer));
	যদি (দৈর্ঘ্য < 0) {
		নির্বাচন(h_errno) {
		ক্ষেত্র HOST_NOT_FOUND:
			ফলাফল = ERRSET_NONAME;
			যাও fail;
		ক্ষেত্র NO_DATA:
			ফলাফল = ERRSET_NODATA;
			যাও fail;
		পূর্বনির্ধারিত:
			ফলাফল = ERRSET_FAIL;
			যাও fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, দৈর্ঘ্য);
	যদি (response == ফাঁকা) {
		ফলাফল = ERRSET_FAIL;
		যাও fail;
	}

	যদি (response->header.qdcount != 1) {
		ফলাফল = ERRSET_FAIL;
		যাও fail;
	}

	/* initialize rrset */
	rrset = calloc(1, আকার(কাঠামো rrsetinfo));
	যদি (rrset == ফাঁকা) {
		ফলাফল = ERRSET_NOMEMORY;
		যাও fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	যদি (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	যদি (rrset->rri_name == ফাঁকা) {
		ফলাফল = ERRSET_NOMEMORY;
		যাও fail;
	}

	/* count answers */
	rrset->rri_nrdatas = গুনতি_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = গুনতি_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    আকার(কাঠামো rdatainfo));
	যদি (rrset->rri_rdatas == ফাঁকা) {
		ফলাফল = ERRSET_NOMEMORY;
		যাও fail;
	}

	/* allocate memory for signatures */
	যদি (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, আকার(কাঠামো rdatainfo));
		যদি (rrset->rri_sigs == ফাঁকা) {
			ফলাফল = ERRSET_NOMEMORY;
			যাও fail;
		}
	}

	/* copy answers & signatures */
	জন্য (rr = response->answer, সূচক_ans = 0, সূচক_sig = 0;
	    rr; rr = rr->পরবর্তী) {

		rdata = ফাঁকা;

		যদি (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[সূচক_ans++];

		যদি (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[সূচক_sig++];

		যদি (rdata) {
			rdata->rdi_দৈর্ঘ্য = rr->আকার_2;
			যদি (rr->আকার_2 != 0) {
				rdata->rdi_তথ্য   = malloc(rr->আকার_2);
				যদি (rdata->rdi_তথ্য == ফাঁকা) {
					ফলাফল = ERRSET_NOMEMORY;
					যাও fail;
				}
				memcpy(rdata->rdi_তথ্য, rr->rdata, rr->আকার_2);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ফেরত (ERRSET_SUCCESS);

fail:
	যদি (rrset != ফাঁকা)
		freerrset(rrset);
	যদি (response != ফাঁকা)
		free_dns_response(response);
	ফেরত (ফলাফল);
}

শূন্য
freerrset(কাঠামো rrsetinfo *rrset)
{
	u_int16_t i;

	যদি (rrset == ফাঁকা)
		ফেরত;

	যদি (rrset->rri_rdatas) {
		জন্য (i = 0; i < rrset->rri_nrdatas; i++) {
			যদি (rrset->rri_rdatas[i].rdi_তথ্য == ফাঁকা)
				বিরতি;
			মুক্ত(rrset->rri_rdatas[i].rdi_তথ্য);
		}
		মুক্ত(rrset->rri_rdatas);
	}

	যদি (rrset->rri_sigs) {
		জন্য (i = 0; i < rrset->rri_nsigs; i++) {
			যদি (rrset->rri_sigs[i].rdi_তথ্য == ফাঁকা)
				বিরতি;
			মুক্ত(rrset->rri_sigs[i].rdi_তথ্য);
		}
		মুক্ত(rrset->rri_sigs);
	}

	যদি (rrset->rri_name)
		মুক্ত(rrset->rri_name);
	মুক্ত(rrset);
}

/*
 * DNS response parsing routines
 */
স্থির কাঠামো dns_response *
parse_dns_response(ধ্রুবক u_char *answer, পূর্ণসংখ্যা আকার_2)
{
	কাঠামো dns_response *resp;
	ধ্রুবক u_char *cp;

	যদি (আকার_2 < HFIXEDSZ)
		ফেরত (ফাঁকা);

	/* allocate memory for the response */
	resp = calloc(1, আকার(*resp));
	যদি (resp == ফাঁকা)
		ফেরত (ফাঁকা);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	memcpy(&resp->header, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->header.qdcount = ntohs(resp->header.qdcount);
	resp->header.ancount = ntohs(resp->header.ancount);
	resp->header.nscount = ntohs(resp->header.nscount);
	resp->header.arcount = ntohs(resp->header.arcount);

	/* there must be at least one query */
	যদি (resp->header.qdcount < 1) {
		free_dns_response(resp);
		ফেরত (ফাঁকা);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, আকার_2, &cp,
	    resp->header.qdcount);
	যদি (resp->header.qdcount && resp->query == ফাঁকা) {
		free_dns_response(resp);
		ফেরত (ফাঁকা);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, আকার_2, &cp,
	    resp->header.ancount);
	যদি (resp->header.ancount && resp->answer == ফাঁকা) {
		free_dns_response(resp);
		ফেরত (ফাঁকা);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, আকার_2, &cp,
	    resp->header.nscount);
	যদি (resp->header.nscount && resp->authority == ফাঁকা) {
		free_dns_response(resp);
		ফেরত (ফাঁকা);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, আকার_2, &cp,
	    resp->header.arcount);
	যদি (resp->header.arcount && resp->additional == ফাঁকা) {
		free_dns_response(resp);
		ফেরত (ফাঁকা);
	}

	ফেরত (resp);
}

স্থির কাঠামো dns_query *
parse_dns_qsection(ধ্রুবক u_char *answer, পূর্ণসংখ্যা আকার_2, ধ্রুবক u_char **cp, পূর্ণসংখ্যা গুনতি)
{
	কাঠামো dns_query *শীর্ষ_2, *curr, *পূর্ব;
	পূর্ণসংখ্যা i, দৈর্ঘ্য;
	অক্ষর name[MAXDNAME];

#define NEED(need) \
	করো { \
		যদি (*cp + need > answer + আকার_2) \
			যাও fail; \
	} যখন (0)

	জন্য (i = 1, শীর্ষ_2 = ফাঁকা, পূর্ব = ফাঁকা; i <= গুনতি; i++, পূর্ব = curr) {
		যদি (*cp >= answer + আকার_2) {
 fail:
			free_dns_query(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}
		/* allocate and initialize struct */
		curr = calloc(1, আকার(কাঠামো dns_query));
		যদি (curr == ফাঁকা)
			যাও fail;
		যদি (শীর্ষ_2 == ফাঁকা)
			শীর্ষ_2 = curr;
		যদি (পূর্ব != ফাঁকা)
			পূর্ব->পরবর্তী = curr;

		/* name */
		দৈর্ঘ্য = dn_expand(answer, answer + আকার_2, *cp, name,
		    আকার(name));
		যদি (দৈর্ঘ্য < 0) {
			free_dns_query(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}
		curr->name = strdup(name);
		যদি (curr->name == ফাঁকা) {
			free_dns_query(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}
		NEED(দৈর্ঘ্য);
		*cp += দৈর্ঘ্য;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#undef NEED

	ফেরত (শীর্ষ_2);
}

স্থির কাঠামো dns_rr *
parse_dns_rrsection(ধ্রুবক u_char *answer, পূর্ণসংখ্যা আকার_2, ধ্রুবক u_char **cp,
    পূর্ণসংখ্যা গুনতি)
{
	কাঠামো dns_rr *শীর্ষ_2, *curr, *পূর্ব;
	পূর্ণসংখ্যা i, দৈর্ঘ্য;
	অক্ষর name[MAXDNAME];

#define NEED(need) \
	করো { \
		যদি (*cp + need > answer + আকার_2) \
			যাও fail; \
	} যখন (0)

	জন্য (i = 1, শীর্ষ_2 = ফাঁকা, পূর্ব = ফাঁকা; i <= গুনতি; i++, পূর্ব = curr) {
		যদি (*cp >= answer + আকার_2) {
 fail:
			free_dns_rr(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}

		/* allocate and initialize struct */
		curr = calloc(1, আকার(কাঠামো dns_rr));
		যদি (curr == ফাঁকা)
			যাও fail;
		যদি (শীর্ষ_2 == ফাঁকা)
			শীর্ষ_2 = curr;
		যদি (পূর্ব != ফাঁকা)
			পূর্ব->পরবর্তী = curr;

		/* name */
		দৈর্ঘ্য = dn_expand(answer, answer + আকার_2, *cp, name,
		    আকার(name));
		যদি (দৈর্ঘ্য < 0) {
			free_dns_rr(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}
		curr->name = strdup(name);
		যদি (curr->name == ফাঁকা) {
			free_dns_rr(শীর্ষ_2);
			ফেরত (ফাঁকা);
		}
		NEED(দৈর্ঘ্য);
		*cp += দৈর্ঘ্য;

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
		curr->আকার_2 = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->আকার_2);
		যদি (curr->আকার_2 != 0) {
			যদি ((curr->rdata = malloc(curr->আকার_2)) == ফাঁকা) {
				free_dns_rr(শীর্ষ_2);
				ফেরত (ফাঁকা);
			}
			memcpy(curr->rdata, *cp, curr->আকার_2);
		}
		*cp += curr->আকার_2;
	}
#undef NEED

	ফেরত (শীর্ষ_2);
}

স্থির শূন্য
free_dns_query(কাঠামো dns_query *p)
{
	কাঠামো dns_query *পরবর্তী;

	যখন (p != ফাঁকা) {
		পরবর্তী = p->পরবর্তী;
		মুক্ত(p->name);
		মুক্ত(p);
		p = পরবর্তী;
	}
}

স্থির শূন্য
free_dns_rr(কাঠামো dns_rr *p)
{
	কাঠামো dns_rr *পরবর্তী;

	যখন (p != ফাঁকা) {
		পরবর্তী = p->পরবর্তী;
		মুক্ত(p->name);
		মুক্ত(p->rdata);
		মুক্ত(p);
		p = পরবর্তী;
	}
}

স্থির শূন্য
free_dns_response(কাঠামো dns_response *p)
{
	যদি (p == ফাঁকা)
		ফেরত;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	মুক্ত(p);
}

স্থির পূর্ণসংখ্যা
গুনতি_dns_rr(কাঠামো dns_rr *p, u_int16_t class, u_int16_t type)
{
	পূর্ণসংখ্যা n = 0;

	যখন(p) {
		যদি (p->class == class && p->type == type)
			n++;
		p = p->পরবর্তী;
	}

	ফেরত (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
