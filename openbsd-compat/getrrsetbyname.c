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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ "getrrsetbyname.h"

#ଯଦି defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
ସଂରଚନା __res_state _res;
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
#ଯଦି !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
ସ୍ଥିର u_int16_t
_getshort(ଅଚଳ u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ଫେରନ୍ତୁ (u);
}

ସ୍ଥିର u_int32_t
_getlong(ଅଚଳ u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ଫେରନ୍ତୁ (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

ସଂରଚନା dns_query {
	ଅକ୍ଷର			*name;
	u_int16_t		type;
	u_int16_t		class;
	ସଂରଚନା dns_query	*next;
};

ସଂରଚନା dns_rr {
	ଅକ୍ଷର			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	ଶୂନ୍ୟ			*rdata;
	ସଂରଚନା dns_rr		*next;
};

ସଂରଚନା dns_response {
	HEADER			header;
	ସଂରଚନା dns_query	*query;
	ସଂରଚନା dns_rr		*answer;
	ସଂରଚନା dns_rr		*authority;
	ସଂରଚନା dns_rr		*additional;
};

ସ୍ଥିର ସଂରଚନା dns_response *parse_dns_response(ଅଚଳ u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ସଂରଚନା dns_query *parse_dns_qsection(ଅଚଳ u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ u_char **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ସଂରଚନା dns_rr *parse_dns_rrsection(ଅଚଳ u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ u_char **,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ସ୍ଥିର ଶୂନ୍ୟ free_dns_query(ସଂରଚନା dns_query *);
ସ୍ଥିର ଶୂନ୍ୟ free_dns_rr(ସଂରଚନା dns_rr *);
ସ୍ଥିର ଶୂନ୍ୟ free_dns_response(ସଂରଚନା dns_response *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_dns_rr(ସଂରଚନା dns_rr *, u_int16_t, u_int16_t);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getrrsetbyname(ଅଚଳ ଅକ୍ଷର *hostname, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdclass,
    unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdtype, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
    ସଂରଚନା rrsetinfo **res)
{
	ସଂରଚନା __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result;
	ସଂରଚନା rrsetinfo *rrset = ଖାଲି;
	ସଂରଚନା dns_response *response = ଖାଲି;
	ସଂରଚନା dns_rr *rr;
	ସଂରଚନା rdatainfo *rdata;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା length;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	ଯଦି (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* don't allow queries of class or type ANY */
	ଯଦି (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* don't allow flags yet, unimplemented */
	ଯଦି (flags) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* initialize resolver */
	ଯଦି ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		ଯାଅ fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ଯଦି (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed ପୂର୍ଣ୍ଣସଂଖ୍ୟା) rdclass, (signed ପୂର୍ଣ୍ଣସଂଖ୍ୟା) rdtype,
	    answer, ଆକାର(answer));
	ଯଦି (length < 0) {
		ବାଛ(h_errno) {
		ସ୍ଥିତି HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			ଯାଅ fail;
		ସ୍ଥିତି NO_DATA:
			result = ERRSET_NODATA;
			ଯାଅ fail;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			result = ERRSET_FAIL;
			ଯାଅ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	ଯଦି (response == ଖାଲି) {
		result = ERRSET_FAIL;
		ଯାଅ fail;
	}

	ଯଦି (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		ଯାଅ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, ଆକାର(ସଂରଚନା rrsetinfo));
	ଯଦି (rrset == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	ଯଦି (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ଯଦି (rrset->rri_name == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ଗଣନା_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ଗଣନା_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    ଆକାର(ସଂରଚନା rdatainfo));
	ଯଦି (rrset->rri_rdatas == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}

	/* allocate memory for signatures */
	ଯଦି (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, ଆକାର(ସଂରଚନା rdatainfo));
		ଯଦି (rrset->rri_sigs == ଖାଲି) {
			result = ERRSET_NOMEMORY;
			ଯାଅ fail;
		}
	}

	/* copy answers & signatures */
	ପାଇଁ (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = ଖାଲି;

		ଯଦି (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		ଯଦି (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		ଯଦି (rdata) {
			rdata->rdi_length = rr->size;
			ଯଦି (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				ଯଦି (rdata->rdi_data == ଖାଲି) {
					result = ERRSET_NOMEMORY;
					ଯାଅ fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ଫେରନ୍ତୁ (ERRSET_SUCCESS);

fail:
	ଯଦି (rrset != ଖାଲି)
		freerrset(rrset);
	ଯଦି (response != ଖାଲି)
		free_dns_response(response);
	ଫେରନ୍ତୁ (result);
}

ଶୂନ୍ୟ
freerrset(ସଂରଚନା rrsetinfo *rrset)
{
	u_int16_t i;

	ଯଦି (rrset == ଖାଲି)
		ଫେରନ୍ତୁ;

	ଯଦି (rrset->rri_rdatas) {
		ପାଇଁ (i = 0; i < rrset->rri_nrdatas; i++) {
			ଯଦି (rrset->rri_rdatas[i].rdi_data == ଖାଲି)
				ଭାଙ୍ଗ;
			ମୁକ୍ତ(rrset->rri_rdatas[i].rdi_data);
		}
		ମୁକ୍ତ(rrset->rri_rdatas);
	}

	ଯଦି (rrset->rri_sigs) {
		ପାଇଁ (i = 0; i < rrset->rri_nsigs; i++) {
			ଯଦି (rrset->rri_sigs[i].rdi_data == ଖାଲି)
				ଭାଙ୍ଗ;
			ମୁକ୍ତ(rrset->rri_sigs[i].rdi_data);
		}
		ମୁକ୍ତ(rrset->rri_sigs);
	}

	ଯଦି (rrset->rri_name)
		ମୁକ୍ତ(rrset->rri_name);
	ମୁକ୍ତ(rrset);
}

/*
 * DNS response parsing routines
 */
ସ୍ଥିର ସଂରଚନା dns_response *
parse_dns_response(ଅଚଳ u_char *answer, ପୂର୍ଣ୍ଣସଂଖ୍ୟା size)
{
	ସଂରଚନା dns_response *resp;
	ଅଚଳ u_char *cp;

	ଯଦି (size < HFIXEDSZ)
		ଫେରନ୍ତୁ (ଖାଲି);

	/* allocate memory for the response */
	resp = calloc(1, ଆକାର(*resp));
	ଯଦି (resp == ଖାଲି)
		ଫେରନ୍ତୁ (ଖାଲି);

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
	ଯଦି (resp->header.qdcount < 1) {
		free_dns_response(resp);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	ଯଦି (resp->header.qdcount && resp->query == ଖାଲି) {
		free_dns_response(resp);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	ଯଦି (resp->header.ancount && resp->answer == ଖାଲି) {
		free_dns_response(resp);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	ଯଦି (resp->header.nscount && resp->authority == ଖାଲି) {
		free_dns_response(resp);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	ଯଦି (resp->header.arcount && resp->additional == ଖାଲି) {
		free_dns_response(resp);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	ଫେରନ୍ତୁ (resp);
}

ସ୍ଥିର ସଂରଚନା dns_query *
parse_dns_qsection(ଅଚଳ u_char *answer, ପୂର୍ଣ୍ଣସଂଖ୍ୟା size, ଅଚଳ u_char **cp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2)
{
	ସଂରଚନା dns_query *head, *curr, *prev;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, length;
	ଅକ୍ଷର name[MAXDNAME];

#define NEED(need) \
	କର { \
		ଯଦି (*cp + need > answer + size) \
			ଯାଅ fail; \
	} ଯେତେବେଳେ (0)

	ପାଇଁ (i = 1, head = ଖାଲି, prev = ଖାଲି; i <= ଗଣନା_2; i++, prev = curr) {
		ଯଦି (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		/* allocate and initialize struct */
		curr = calloc(1, ଆକାର(ସଂରଚନା dns_query));
		ଯଦି (curr == ଖାଲି)
			ଯାଅ fail;
		ଯଦି (head == ଖାଲି)
			head = curr;
		ଯଦି (prev != ଖାଲି)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    ଆକାର(name));
		ଯଦି (length < 0) {
			free_dns_query(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		curr->name = strdup(name);
		ଯଦି (curr->name == ଖାଲି) {
			free_dns_query(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		NEED(length);
		*cp += length;

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

	ଫେରନ୍ତୁ (head);
}

ସ୍ଥିର ସଂରଚନା dns_rr *
parse_dns_rrsection(ଅଚଳ u_char *answer, ପୂର୍ଣ୍ଣସଂଖ୍ୟା size, ଅଚଳ u_char **cp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2)
{
	ସଂରଚନା dns_rr *head, *curr, *prev;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, length;
	ଅକ୍ଷର name[MAXDNAME];

#define NEED(need) \
	କର { \
		ଯଦି (*cp + need > answer + size) \
			ଯାଅ fail; \
	} ଯେତେବେଳେ (0)

	ପାଇଁ (i = 1, head = ଖାଲି, prev = ଖାଲି; i <= ଗଣନା_2; i++, prev = curr) {
		ଯଦି (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}

		/* allocate and initialize struct */
		curr = calloc(1, ଆକାର(ସଂରଚନା dns_rr));
		ଯଦି (curr == ଖାଲି)
			ଯାଅ fail;
		ଯଦି (head == ଖାଲି)
			head = curr;
		ଯଦି (prev != ଖାଲି)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    ଆକାର(name));
		ଯଦି (length < 0) {
			free_dns_rr(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		curr->name = strdup(name);
		ଯଦି (curr->name == ଖାଲି) {
			free_dns_rr(head);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		NEED(length);
		*cp += length;

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
		curr->size = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->size);
		ଯଦି (curr->size != 0) {
			ଯଦି ((curr->rdata = malloc(curr->size)) == ଖାଲି) {
				free_dns_rr(head);
				ଫେରନ୍ତୁ (ଖାଲି);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	ଫେରନ୍ତୁ (head);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dns_query(ସଂରଚନା dns_query *p)
{
	ସଂରଚନା dns_query *next;

	ଯେତେବେଳେ (p != ଖାଲି) {
		next = p->next;
		ମୁକ୍ତ(p->name);
		ମୁକ୍ତ(p);
		p = next;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dns_rr(ସଂରଚନା dns_rr *p)
{
	ସଂରଚନା dns_rr *next;

	ଯେତେବେଳେ (p != ଖାଲି) {
		next = p->next;
		ମୁକ୍ତ(p->name);
		ମୁକ୍ତ(p->rdata);
		ମୁକ୍ତ(p);
		p = next;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dns_response(ସଂରଚନା dns_response *p)
{
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	ମୁକ୍ତ(p);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଗଣନା_dns_rr(ସଂରଚନା dns_rr *p, u_int16_t class, u_int16_t type)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା n = 0;

	ଯେତେବେଳେ(p) {
		ଯଦି (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	ଫେରନ୍ତୁ (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
