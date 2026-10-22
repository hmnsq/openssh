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

#شامل "includes.h"

#اگر !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#شامل <stdlib.h>
#شامل <string.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل "getrrsetbyname.h"

#اگر defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
بیرونی صحیح h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
ساختار __res_state _res;
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
#اگر !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
ایستا u_int16_t
_getshort(ثابت u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	بازگشت (u);
}

ایستا u_int32_t
_getlong(ثابت u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	بازگشت (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

ساختار dns_query {
	نویسه			*name;
	u_int16_t		type;
	u_int16_t		class;
	ساختار dns_query	*next;
};

ساختار dns_rr {
	نویسه			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	تهی			*rdata;
	ساختار dns_rr		*next;
};

ساختار dns_response {
	HEADER			header;
	ساختار dns_query	*query;
	ساختار dns_rr		*answer;
	ساختار dns_rr		*authority;
	ساختار dns_rr		*additional;
};

ایستا ساختار dns_response *parse_dns_response(ثابت u_char *, صحیح);
ایستا ساختار dns_query *parse_dns_qsection(ثابت u_char *, صحیح,
    ثابت u_char **, صحیح);
ایستا ساختار dns_rr *parse_dns_rrsection(ثابت u_char *, صحیح, ثابت u_char **,
    صحیح);

ایستا تهی free_dns_query(ساختار dns_query *);
ایستا تهی free_dns_rr(ساختار dns_rr *);
ایستا تهی free_dns_response(ساختار dns_response *);

ایستا صحیح شمار_dns_rr(ساختار dns_rr *, u_int16_t, u_int16_t);

صحیح
getrrsetbyname(ثابت نویسه *hostname, unsigned صحیح rdclass,
    unsigned صحیح rdtype, unsigned صحیح flags,
    ساختار rrsetinfo **res)
{
	ساختار __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	صحیح result;
	ساختار rrsetinfo *rrset = پوچ;
	ساختار dns_response *response = پوچ;
	ساختار dns_rr *rr;
	ساختار rdatainfo *rdata;
	صحیح length;
	unsigned صحیح index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	اگر (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* don't allow queries of class or type ANY */
	اگر (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* don't allow flags yet, unimplemented */
	اگر (flags) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* initialize resolver */
	اگر ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		برو fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	اگر (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed صحیح) rdclass, (signed صحیح) rdtype,
	    answer, اندازه(answer));
	اگر (length < 0) {
		انتخاب(h_errno) {
		حالت HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			برو fail;
		حالت NO_DATA:
			result = ERRSET_NODATA;
			برو fail;
		پیشفرض:
			result = ERRSET_FAIL;
			برو fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	اگر (response == پوچ) {
		result = ERRSET_FAIL;
		برو fail;
	}

	اگر (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		برو fail;
	}

	/* initialize rrset */
	rrset = calloc(1, اندازه(ساختار rrsetinfo));
	اگر (rrset == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	اگر (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	اگر (rrset->rri_name == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}

	/* count answers */
	rrset->rri_nrdatas = شمار_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = شمار_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    اندازه(ساختار rdatainfo));
	اگر (rrset->rri_rdatas == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}

	/* allocate memory for signatures */
	اگر (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, اندازه(ساختار rdatainfo));
		اگر (rrset->rri_sigs == پوچ) {
			result = ERRSET_NOMEMORY;
			برو fail;
		}
	}

	/* copy answers & signatures */
	برای (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = پوچ;

		اگر (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		اگر (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		اگر (rdata) {
			rdata->rdi_length = rr->size;
			اگر (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				اگر (rdata->rdi_data == پوچ) {
					result = ERRSET_NOMEMORY;
					برو fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	بازگشت (ERRSET_SUCCESS);

fail:
	اگر (rrset != پوچ)
		freerrset(rrset);
	اگر (response != پوچ)
		free_dns_response(response);
	بازگشت (result);
}

تهی
freerrset(ساختار rrsetinfo *rrset)
{
	u_int16_t i;

	اگر (rrset == پوچ)
		بازگشت;

	اگر (rrset->rri_rdatas) {
		برای (i = 0; i < rrset->rri_nrdatas; i++) {
			اگر (rrset->rri_rdatas[i].rdi_data == پوچ)
				بشکن;
			آزاد(rrset->rri_rdatas[i].rdi_data);
		}
		آزاد(rrset->rri_rdatas);
	}

	اگر (rrset->rri_sigs) {
		برای (i = 0; i < rrset->rri_nsigs; i++) {
			اگر (rrset->rri_sigs[i].rdi_data == پوچ)
				بشکن;
			آزاد(rrset->rri_sigs[i].rdi_data);
		}
		آزاد(rrset->rri_sigs);
	}

	اگر (rrset->rri_name)
		آزاد(rrset->rri_name);
	آزاد(rrset);
}

/*
 * DNS response parsing routines
 */
ایستا ساختار dns_response *
parse_dns_response(ثابت u_char *answer, صحیح size)
{
	ساختار dns_response *resp;
	ثابت u_char *cp;

	اگر (size < HFIXEDSZ)
		بازگشت (پوچ);

	/* allocate memory for the response */
	resp = calloc(1, اندازه(*resp));
	اگر (resp == پوچ)
		بازگشت (پوچ);

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
	اگر (resp->header.qdcount < 1) {
		free_dns_response(resp);
		بازگشت (پوچ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	اگر (resp->header.qdcount && resp->query == پوچ) {
		free_dns_response(resp);
		بازگشت (پوچ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	اگر (resp->header.ancount && resp->answer == پوچ) {
		free_dns_response(resp);
		بازگشت (پوچ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	اگر (resp->header.nscount && resp->authority == پوچ) {
		free_dns_response(resp);
		بازگشت (پوچ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	اگر (resp->header.arcount && resp->additional == پوچ) {
		free_dns_response(resp);
		بازگشت (پوچ);
	}

	بازگشت (resp);
}

ایستا ساختار dns_query *
parse_dns_qsection(ثابت u_char *answer, صحیح size, ثابت u_char **cp, صحیح شمار)
{
	ساختار dns_query *head, *curr, *prev;
	صحیح i, length;
	نویسه name[MAXDNAME];

#define NEED(need) \
	انجامبده { \
		اگر (*cp + need > answer + size) \
			برو fail; \
	} وقتی (0)

	برای (i = 1, head = پوچ, prev = پوچ; i <= شمار; i++, prev = curr) {
		اگر (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			بازگشت (پوچ);
		}
		/* allocate and initialize struct */
		curr = calloc(1, اندازه(ساختار dns_query));
		اگر (curr == پوچ)
			برو fail;
		اگر (head == پوچ)
			head = curr;
		اگر (prev != پوچ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    اندازه(name));
		اگر (length < 0) {
			free_dns_query(head);
			بازگشت (پوچ);
		}
		curr->name = strdup(name);
		اگر (curr->name == پوچ) {
			free_dns_query(head);
			بازگشت (پوچ);
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

	بازگشت (head);
}

ایستا ساختار dns_rr *
parse_dns_rrsection(ثابت u_char *answer, صحیح size, ثابت u_char **cp,
    صحیح شمار)
{
	ساختار dns_rr *head, *curr, *prev;
	صحیح i, length;
	نویسه name[MAXDNAME];

#define NEED(need) \
	انجامبده { \
		اگر (*cp + need > answer + size) \
			برو fail; \
	} وقتی (0)

	برای (i = 1, head = پوچ, prev = پوچ; i <= شمار; i++, prev = curr) {
		اگر (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			بازگشت (پوچ);
		}

		/* allocate and initialize struct */
		curr = calloc(1, اندازه(ساختار dns_rr));
		اگر (curr == پوچ)
			برو fail;
		اگر (head == پوچ)
			head = curr;
		اگر (prev != پوچ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    اندازه(name));
		اگر (length < 0) {
			free_dns_rr(head);
			بازگشت (پوچ);
		}
		curr->name = strdup(name);
		اگر (curr->name == پوچ) {
			free_dns_rr(head);
			بازگشت (پوچ);
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
		اگر (curr->size != 0) {
			اگر ((curr->rdata = malloc(curr->size)) == پوچ) {
				free_dns_rr(head);
				بازگشت (پوچ);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	بازگشت (head);
}

ایستا تهی
free_dns_query(ساختار dns_query *p)
{
	ساختار dns_query *next;

	وقتی (p != پوچ) {
		next = p->next;
		آزاد(p->name);
		آزاد(p);
		p = next;
	}
}

ایستا تهی
free_dns_rr(ساختار dns_rr *p)
{
	ساختار dns_rr *next;

	وقتی (p != پوچ) {
		next = p->next;
		آزاد(p->name);
		آزاد(p->rdata);
		آزاد(p);
		p = next;
	}
}

ایستا تهی
free_dns_response(ساختار dns_response *p)
{
	اگر (p == پوچ)
		بازگشت;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	آزاد(p);
}

ایستا صحیح
شمار_dns_rr(ساختار dns_rr *p, u_int16_t class, u_int16_t type)
{
	صحیح n = 0;

	وقتی(p) {
		اگر (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	بازگشت (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
