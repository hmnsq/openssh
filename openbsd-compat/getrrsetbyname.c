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

#அந்தர்பாவ "includes.h"

#எனில் !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ "getrrsetbyname.h"

#எனில் defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
வெளி முழு h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
கட்டமைப்பு __res_state _res;
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
#எனில் !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
நிலையான u_int16_t
_getshort(மாறிலி u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	திரும்பு (u);
}

நிலையான u_int32_t
_getlong(மாறிலி u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	திரும்பு (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

கட்டமைப்பு dns_query {
	எழுத்து			*name;
	u_int16_t		type;
	u_int16_t		class;
	கட்டமைப்பு dns_query	*next;
};

கட்டமைப்பு dns_rr {
	எழுத்து			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	வெறுமை			*rdata;
	கட்டமைப்பு dns_rr		*next;
};

கட்டமைப்பு dns_response {
	HEADER			header;
	கட்டமைப்பு dns_query	*query;
	கட்டமைப்பு dns_rr		*answer;
	கட்டமைப்பு dns_rr		*authority;
	கட்டமைப்பு dns_rr		*additional;
};

நிலையான கட்டமைப்பு dns_response *parse_dns_response(மாறிலி u_char *, முழு);
நிலையான கட்டமைப்பு dns_query *parse_dns_qsection(மாறிலி u_char *, முழு,
    மாறிலி u_char **, முழு);
நிலையான கட்டமைப்பு dns_rr *parse_dns_rrsection(மாறிலி u_char *, முழு, மாறிலி u_char **,
    முழு);

நிலையான வெறுமை free_dns_query(கட்டமைப்பு dns_query *);
நிலையான வெறுமை free_dns_rr(கட்டமைப்பு dns_rr *);
நிலையான வெறுமை free_dns_response(கட்டமைப்பு dns_response *);

நிலையான முழு மொத்தம்_dns_rr(கட்டமைப்பு dns_rr *, u_int16_t, u_int16_t);

முழு
getrrsetbyname(மாறிலி எழுத்து *hostname, unsigned முழு rdclass,
    unsigned முழு rdtype, unsigned முழு flags,
    கட்டமைப்பு rrsetinfo **res)
{
	கட்டமைப்பு __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	முழு result;
	கட்டமைப்பு rrsetinfo *rrset = வெற்று;
	கட்டமைப்பு dns_response *response = வெற்று;
	கட்டமைப்பு dns_rr *rr;
	கட்டமைப்பு rdatainfo *rdata;
	முழு length;
	unsigned முழு index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	எனில் (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		செல் fail;
	}

	/* don't allow queries of class or type ANY */
	எனில் (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		செல் fail;
	}

	/* don't allow flags yet, unimplemented */
	எனில் (flags) {
		result = ERRSET_INVAL;
		செல் fail;
	}

	/* initialize resolver */
	எனில் ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		செல் fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	எனில் (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed முழு) rdclass, (signed முழு) rdtype,
	    answer, அளவு(answer));
	எனில் (length < 0) {
		தேர்வு(h_errno) {
		நிலை HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			செல் fail;
		நிலை NO_DATA:
			result = ERRSET_NODATA;
			செல் fail;
		இயல்பு:
			result = ERRSET_FAIL;
			செல் fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	எனில் (response == வெற்று) {
		result = ERRSET_FAIL;
		செல் fail;
	}

	எனில் (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		செல் fail;
	}

	/* initialize rrset */
	rrset = calloc(1, அளவு(கட்டமைப்பு rrsetinfo));
	எனில் (rrset == வெற்று) {
		result = ERRSET_NOMEMORY;
		செல் fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	எனில் (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	எனில் (rrset->rri_name == வெற்று) {
		result = ERRSET_NOMEMORY;
		செல் fail;
	}

	/* count answers */
	rrset->rri_nrdatas = மொத்தம்_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = மொத்தம்_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    அளவு(கட்டமைப்பு rdatainfo));
	எனில் (rrset->rri_rdatas == வெற்று) {
		result = ERRSET_NOMEMORY;
		செல் fail;
	}

	/* allocate memory for signatures */
	எனில் (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, அளவு(கட்டமைப்பு rdatainfo));
		எனில் (rrset->rri_sigs == வெற்று) {
			result = ERRSET_NOMEMORY;
			செல் fail;
		}
	}

	/* copy answers & signatures */
	க்கு (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = வெற்று;

		எனில் (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		எனில் (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		எனில் (rdata) {
			rdata->rdi_length = rr->size;
			எனில் (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				எனில் (rdata->rdi_data == வெற்று) {
					result = ERRSET_NOMEMORY;
					செல் fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	திரும்பு (ERRSET_SUCCESS);

fail:
	எனில் (rrset != வெற்று)
		freerrset(rrset);
	எனில் (response != வெற்று)
		free_dns_response(response);
	திரும்பு (result);
}

வெறுமை
freerrset(கட்டமைப்பு rrsetinfo *rrset)
{
	u_int16_t i;

	எனில் (rrset == வெற்று)
		திரும்பு;

	எனில் (rrset->rri_rdatas) {
		க்கு (i = 0; i < rrset->rri_nrdatas; i++) {
			எனில் (rrset->rri_rdatas[i].rdi_data == வெற்று)
				நிறுத்து;
			விடுவி(rrset->rri_rdatas[i].rdi_data);
		}
		விடுவி(rrset->rri_rdatas);
	}

	எனில் (rrset->rri_sigs) {
		க்கு (i = 0; i < rrset->rri_nsigs; i++) {
			எனில் (rrset->rri_sigs[i].rdi_data == வெற்று)
				நிறுத்து;
			விடுவி(rrset->rri_sigs[i].rdi_data);
		}
		விடுவி(rrset->rri_sigs);
	}

	எனில் (rrset->rri_name)
		விடுவி(rrset->rri_name);
	விடுவி(rrset);
}

/*
 * DNS response parsing routines
 */
நிலையான கட்டமைப்பு dns_response *
parse_dns_response(மாறிலி u_char *answer, முழு size)
{
	கட்டமைப்பு dns_response *resp;
	மாறிலி u_char *cp;

	எனில் (size < HFIXEDSZ)
		திரும்பு (வெற்று);

	/* allocate memory for the response */
	resp = calloc(1, அளவு(*resp));
	எனில் (resp == வெற்று)
		திரும்பு (வெற்று);

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
	எனில் (resp->header.qdcount < 1) {
		free_dns_response(resp);
		திரும்பு (வெற்று);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	எனில் (resp->header.qdcount && resp->query == வெற்று) {
		free_dns_response(resp);
		திரும்பு (வெற்று);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	எனில் (resp->header.ancount && resp->answer == வெற்று) {
		free_dns_response(resp);
		திரும்பு (வெற்று);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	எனில் (resp->header.nscount && resp->authority == வெற்று) {
		free_dns_response(resp);
		திரும்பு (வெற்று);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	எனில் (resp->header.arcount && resp->additional == வெற்று) {
		free_dns_response(resp);
		திரும்பு (வெற்று);
	}

	திரும்பு (resp);
}

நிலையான கட்டமைப்பு dns_query *
parse_dns_qsection(மாறிலி u_char *answer, முழு size, மாறிலி u_char **cp, முழு மொத்தம்)
{
	கட்டமைப்பு dns_query *head, *curr, *prev;
	முழு i, length;
	எழுத்து name[MAXDNAME];

#define NEED(need) \
	செய் { \
		எனில் (*cp + need > answer + size) \
			செல் fail; \
	} போது (0)

	க்கு (i = 1, head = வெற்று, prev = வெற்று; i <= மொத்தம்; i++, prev = curr) {
		எனில் (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			திரும்பு (வெற்று);
		}
		/* allocate and initialize struct */
		curr = calloc(1, அளவு(கட்டமைப்பு dns_query));
		எனில் (curr == வெற்று)
			செல் fail;
		எனில் (head == வெற்று)
			head = curr;
		எனில் (prev != வெற்று)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    அளவு(name));
		எனில் (length < 0) {
			free_dns_query(head);
			திரும்பு (வெற்று);
		}
		curr->name = strdup(name);
		எனில் (curr->name == வெற்று) {
			free_dns_query(head);
			திரும்பு (வெற்று);
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

	திரும்பு (head);
}

நிலையான கட்டமைப்பு dns_rr *
parse_dns_rrsection(மாறிலி u_char *answer, முழு size, மாறிலி u_char **cp,
    முழு மொத்தம்)
{
	கட்டமைப்பு dns_rr *head, *curr, *prev;
	முழு i, length;
	எழுத்து name[MAXDNAME];

#define NEED(need) \
	செய் { \
		எனில் (*cp + need > answer + size) \
			செல் fail; \
	} போது (0)

	க்கு (i = 1, head = வெற்று, prev = வெற்று; i <= மொத்தம்; i++, prev = curr) {
		எனில் (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			திரும்பு (வெற்று);
		}

		/* allocate and initialize struct */
		curr = calloc(1, அளவு(கட்டமைப்பு dns_rr));
		எனில் (curr == வெற்று)
			செல் fail;
		எனில் (head == வெற்று)
			head = curr;
		எனில் (prev != வெற்று)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    அளவு(name));
		எனில் (length < 0) {
			free_dns_rr(head);
			திரும்பு (வெற்று);
		}
		curr->name = strdup(name);
		எனில் (curr->name == வெற்று) {
			free_dns_rr(head);
			திரும்பு (வெற்று);
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
		எனில் (curr->size != 0) {
			எனில் ((curr->rdata = malloc(curr->size)) == வெற்று) {
				free_dns_rr(head);
				திரும்பு (வெற்று);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	திரும்பு (head);
}

நிலையான வெறுமை
free_dns_query(கட்டமைப்பு dns_query *p)
{
	கட்டமைப்பு dns_query *next;

	போது (p != வெற்று) {
		next = p->next;
		விடுவி(p->name);
		விடுவி(p);
		p = next;
	}
}

நிலையான வெறுமை
free_dns_rr(கட்டமைப்பு dns_rr *p)
{
	கட்டமைப்பு dns_rr *next;

	போது (p != வெற்று) {
		next = p->next;
		விடுவி(p->name);
		விடுவி(p->rdata);
		விடுவி(p);
		p = next;
	}
}

நிலையான வெறுமை
free_dns_response(கட்டமைப்பு dns_response *p)
{
	எனில் (p == வெற்று)
		திரும்பு;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	விடுவி(p);
}

நிலையான முழு
மொத்தம்_dns_rr(கட்டமைப்பு dns_rr *p, u_int16_t class, u_int16_t type)
{
	முழு n = 0;

	போது(p) {
		எனில் (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	திரும்பு (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
