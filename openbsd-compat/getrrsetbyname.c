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
বাহ্য পূর্ণাঙ্ক h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
সংরচনা __res_state _res;
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
_getshort(ধ্রুব u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	প্রত্যাগম (u);
}

স্থির u_int32_t
_getlong(ধ্রুব u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	প্রত্যাগম (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

সংরচনা dns_query {
	বর্ণ			*name;
	u_int16_t		type;
	u_int16_t		class;
	সংরচনা dns_query	*next;
};

সংরচনা dns_rr {
	বর্ণ			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	শূন্য			*rdata;
	সংরচনা dns_rr		*next;
};

সংরচনা dns_response {
	HEADER			header;
	সংরচনা dns_query	*query;
	সংরচনা dns_rr		*answer;
	সংরচনা dns_rr		*authority;
	সংরচনা dns_rr		*additional;
};

স্থির সংরচনা dns_response *parse_dns_response(ধ্রুব u_char *, পূর্ণাঙ্ক);
স্থির সংরচনা dns_query *parse_dns_qsection(ধ্রুব u_char *, পূর্ণাঙ্ক,
    ধ্রুব u_char **, পূর্ণাঙ্ক);
স্থির সংরচনা dns_rr *parse_dns_rrsection(ধ্রুব u_char *, পূর্ণাঙ্ক, ধ্রুব u_char **,
    পূর্ণাঙ্ক);

স্থির শূন্য free_dns_query(সংরচনা dns_query *);
স্থির শূন্য free_dns_rr(সংরচনা dns_rr *);
স্থির শূন্য free_dns_response(সংরচনা dns_response *);

স্থির পূর্ণাঙ্ক গুনতি_dns_rr(সংরচনা dns_rr *, u_int16_t, u_int16_t);

পূর্ণাঙ্ক
getrrsetbyname(ধ্রুব বর্ণ *hostname, unsigned পূর্ণাঙ্ক rdclass,
    unsigned পূর্ণাঙ্ক rdtype, unsigned পূর্ণাঙ্ক flags,
    সংরচনা rrsetinfo **res)
{
	সংরচনা __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	পূর্ণাঙ্ক result;
	সংরচনা rrsetinfo *rrset = রিক্ত;
	সংরচনা dns_response *response = রিক্ত;
	সংরচনা dns_rr *rr;
	সংরচনা rdatainfo *rdata;
	পূর্ণাঙ্ক length;
	unsigned পূর্ণাঙ্ক index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	যদি (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* don't allow queries of class or type ANY */
	যদি (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* don't allow flags yet, unimplemented */
	যদি (flags) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* initialize resolver */
	যদি ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		গচ্ছ fail;
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
	length = res_query(hostname, (signed পূর্ণাঙ্ক) rdclass, (signed পূর্ণাঙ্ক) rdtype,
	    answer, পরিমাণ(answer));
	যদি (length < 0) {
		বিকল্প(h_errno) {
		পক্ষ HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			গচ্ছ fail;
		পক্ষ NO_DATA:
			result = ERRSET_NODATA;
			গচ্ছ fail;
		স্বভাব:
			result = ERRSET_FAIL;
			গচ্ছ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	যদি (response == রিক্ত) {
		result = ERRSET_FAIL;
		গচ্ছ fail;
	}

	যদি (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		গচ্ছ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, পরিমাণ(সংরচনা rrsetinfo));
	যদি (rrset == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
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
	যদি (rrset->rri_name == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = গুনতি_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = গুনতি_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    পরিমাণ(সংরচনা rdatainfo));
	যদি (rrset->rri_rdatas == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
	}

	/* allocate memory for signatures */
	যদি (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, পরিমাণ(সংরচনা rdatainfo));
		যদি (rrset->rri_sigs == রিক্ত) {
			result = ERRSET_NOMEMORY;
			গচ্ছ fail;
		}
	}

	/* copy answers & signatures */
	প্রতি (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = রিক্ত;

		যদি (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		যদি (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		যদি (rdata) {
			rdata->rdi_length = rr->size;
			যদি (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				যদি (rdata->rdi_data == রিক্ত) {
					result = ERRSET_NOMEMORY;
					গচ্ছ fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	প্রত্যাগম (ERRSET_SUCCESS);

fail:
	যদি (rrset != রিক্ত)
		freerrset(rrset);
	যদি (response != রিক্ত)
		free_dns_response(response);
	প্রত্যাগম (result);
}

শূন্য
freerrset(সংরচনা rrsetinfo *rrset)
{
	u_int16_t i;

	যদি (rrset == রিক্ত)
		প্রত্যাগম;

	যদি (rrset->rri_rdatas) {
		প্রতি (i = 0; i < rrset->rri_nrdatas; i++) {
			যদি (rrset->rri_rdatas[i].rdi_data == রিক্ত)
				ভঙ্গ;
			মুক্ত(rrset->rri_rdatas[i].rdi_data);
		}
		মুক্ত(rrset->rri_rdatas);
	}

	যদি (rrset->rri_sigs) {
		প্রতি (i = 0; i < rrset->rri_nsigs; i++) {
			যদি (rrset->rri_sigs[i].rdi_data == রিক্ত)
				ভঙ্গ;
			মুক্ত(rrset->rri_sigs[i].rdi_data);
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
স্থির সংরচনা dns_response *
parse_dns_response(ধ্রুব u_char *answer, পূর্ণাঙ্ক size)
{
	সংরচনা dns_response *resp;
	ধ্রুব u_char *cp;

	যদি (size < HFIXEDSZ)
		প্রত্যাগম (রিক্ত);

	/* allocate memory for the response */
	resp = calloc(1, পরিমাণ(*resp));
	যদি (resp == রিক্ত)
		প্রত্যাগম (রিক্ত);

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
		প্রত্যাগম (রিক্ত);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	যদি (resp->header.qdcount && resp->query == রিক্ত) {
		free_dns_response(resp);
		প্রত্যাগম (রিক্ত);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	যদি (resp->header.ancount && resp->answer == রিক্ত) {
		free_dns_response(resp);
		প্রত্যাগম (রিক্ত);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	যদি (resp->header.nscount && resp->authority == রিক্ত) {
		free_dns_response(resp);
		প্রত্যাগম (রিক্ত);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	যদি (resp->header.arcount && resp->additional == রিক্ত) {
		free_dns_response(resp);
		প্রত্যাগম (রিক্ত);
	}

	প্রত্যাগম (resp);
}

স্থির সংরচনা dns_query *
parse_dns_qsection(ধ্রুব u_char *answer, পূর্ণাঙ্ক size, ধ্রুব u_char **cp, পূর্ণাঙ্ক গুনতি)
{
	সংরচনা dns_query *head, *curr, *prev;
	পূর্ণাঙ্ক i, length;
	বর্ণ name[MAXDNAME];

#define NEED(need) \
	কুরু { \
		যদি (*cp + need > answer + size) \
			গচ্ছ fail; \
	} যাবত্ (0)

	প্রতি (i = 1, head = রিক্ত, prev = রিক্ত; i <= গুনতি; i++, prev = curr) {
		যদি (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			প্রত্যাগম (রিক্ত);
		}
		/* allocate and initialize struct */
		curr = calloc(1, পরিমাণ(সংরচনা dns_query));
		যদি (curr == রিক্ত)
			গচ্ছ fail;
		যদি (head == রিক্ত)
			head = curr;
		যদি (prev != রিক্ত)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    পরিমাণ(name));
		যদি (length < 0) {
			free_dns_query(head);
			প্রত্যাগম (রিক্ত);
		}
		curr->name = strdup(name);
		যদি (curr->name == রিক্ত) {
			free_dns_query(head);
			প্রত্যাগম (রিক্ত);
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

	প্রত্যাগম (head);
}

স্থির সংরচনা dns_rr *
parse_dns_rrsection(ধ্রুব u_char *answer, পূর্ণাঙ্ক size, ধ্রুব u_char **cp,
    পূর্ণাঙ্ক গুনতি)
{
	সংরচনা dns_rr *head, *curr, *prev;
	পূর্ণাঙ্ক i, length;
	বর্ণ name[MAXDNAME];

#define NEED(need) \
	কুরু { \
		যদি (*cp + need > answer + size) \
			গচ্ছ fail; \
	} যাবত্ (0)

	প্রতি (i = 1, head = রিক্ত, prev = রিক্ত; i <= গুনতি; i++, prev = curr) {
		যদি (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			প্রত্যাগম (রিক্ত);
		}

		/* allocate and initialize struct */
		curr = calloc(1, পরিমাণ(সংরচনা dns_rr));
		যদি (curr == রিক্ত)
			গচ্ছ fail;
		যদি (head == রিক্ত)
			head = curr;
		যদি (prev != রিক্ত)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    পরিমাণ(name));
		যদি (length < 0) {
			free_dns_rr(head);
			প্রত্যাগম (রিক্ত);
		}
		curr->name = strdup(name);
		যদি (curr->name == রিক্ত) {
			free_dns_rr(head);
			প্রত্যাগম (রিক্ত);
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
		যদি (curr->size != 0) {
			যদি ((curr->rdata = malloc(curr->size)) == রিক্ত) {
				free_dns_rr(head);
				প্রত্যাগম (রিক্ত);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	প্রত্যাগম (head);
}

স্থির শূন্য
free_dns_query(সংরচনা dns_query *p)
{
	সংরচনা dns_query *next;

	যাবত্ (p != রিক্ত) {
		next = p->next;
		মুক্ত(p->name);
		মুক্ত(p);
		p = next;
	}
}

স্থির শূন্য
free_dns_rr(সংরচনা dns_rr *p)
{
	সংরচনা dns_rr *next;

	যাবত্ (p != রিক্ত) {
		next = p->next;
		মুক্ত(p->name);
		মুক্ত(p->rdata);
		মুক্ত(p);
		p = next;
	}
}

স্থির শূন্য
free_dns_response(সংরচনা dns_response *p)
{
	যদি (p == রিক্ত)
		প্রত্যাগম;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	মুক্ত(p);
}

স্থির পূর্ণাঙ্ক
গুনতি_dns_rr(সংরচনা dns_rr *p, u_int16_t class, u_int16_t type)
{
	পূর্ণাঙ্ক n = 0;

	যাবত্(p) {
		যদি (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	প্রত্যাগম (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
