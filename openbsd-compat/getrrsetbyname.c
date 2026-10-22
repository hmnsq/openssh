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

#અન્તર્ભાવ "includes.h"

#જો !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ "getrrsetbyname.h"

#જો defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
બાહ્ય પૂર્ણાંક h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
સંરચના __res_state _res;
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
#જો !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
સ્થિર u_int16_t
_getshort(અચલ u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	પાછા (u);
}

સ્થિર u_int32_t
_getlong(અચલ u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	પાછા (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

સંરચના dns_query {
	અક્ષર			*name;
	u_int16_t		type;
	u_int16_t		class;
	સંરચના dns_query	*next;
};

સંરચના dns_rr {
	અક્ષર			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	શૂન્ય			*rdata;
	સંરચના dns_rr		*next;
};

સંરચના dns_response {
	HEADER			header;
	સંરચના dns_query	*query;
	સંરચના dns_rr		*answer;
	સંરચના dns_rr		*authority;
	સંરચના dns_rr		*additional;
};

સ્થિર સંરચના dns_response *parse_dns_response(અચલ u_char *, પૂર્ણાંક);
સ્થિર સંરચના dns_query *parse_dns_qsection(અચલ u_char *, પૂર્ણાંક,
    અચલ u_char **, પૂર્ણાંક);
સ્થિર સંરચના dns_rr *parse_dns_rrsection(અચલ u_char *, પૂર્ણાંક, અચલ u_char **,
    પૂર્ણાંક);

સ્થિર શૂન્ય free_dns_query(સંરચના dns_query *);
સ્થિર શૂન્ય free_dns_rr(સંરચના dns_rr *);
સ્થિર શૂન્ય free_dns_response(સંરચના dns_response *);

સ્થિર પૂર્ણાંક ગણતરી_dns_rr(સંરચના dns_rr *, u_int16_t, u_int16_t);

પૂર્ણાંક
getrrsetbyname(અચલ અક્ષર *hostname, unsigned પૂર્ણાંક rdclass,
    unsigned પૂર્ણાંક rdtype, unsigned પૂર્ણાંક flags,
    સંરચના rrsetinfo **res)
{
	સંરચના __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	પૂર્ણાંક result;
	સંરચના rrsetinfo *rrset = ખાલી;
	સંરચના dns_response *response = ખાલી;
	સંરચના dns_rr *rr;
	સંરચના rdatainfo *rdata;
	પૂર્ણાંક length;
	unsigned પૂર્ણાંક index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	જો (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		જાઓ fail;
	}

	/* don't allow queries of class or type ANY */
	જો (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		જાઓ fail;
	}

	/* don't allow flags yet, unimplemented */
	જો (flags) {
		result = ERRSET_INVAL;
		જાઓ fail;
	}

	/* initialize resolver */
	જો ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		જાઓ fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	જો (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed પૂર્ણાંક) rdclass, (signed પૂર્ણાંક) rdtype,
	    answer, કદ(answer));
	જો (length < 0) {
		પસંદગી(h_errno) {
		સ્થિતિ HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			જાઓ fail;
		સ્થિતિ NO_DATA:
			result = ERRSET_NODATA;
			જાઓ fail;
		મૂળભૂત:
			result = ERRSET_FAIL;
			જાઓ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	જો (response == ખાલી) {
		result = ERRSET_FAIL;
		જાઓ fail;
	}

	જો (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		જાઓ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, કદ(સંરચના rrsetinfo));
	જો (rrset == ખાલી) {
		result = ERRSET_NOMEMORY;
		જાઓ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	જો (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	જો (rrset->rri_name == ખાલી) {
		result = ERRSET_NOMEMORY;
		જાઓ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ગણતરી_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ગણતરી_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    કદ(સંરચના rdatainfo));
	જો (rrset->rri_rdatas == ખાલી) {
		result = ERRSET_NOMEMORY;
		જાઓ fail;
	}

	/* allocate memory for signatures */
	જો (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, કદ(સંરચના rdatainfo));
		જો (rrset->rri_sigs == ખાલી) {
			result = ERRSET_NOMEMORY;
			જાઓ fail;
		}
	}

	/* copy answers & signatures */
	માટે (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = ખાલી;

		જો (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		જો (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		જો (rdata) {
			rdata->rdi_length = rr->size;
			જો (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				જો (rdata->rdi_data == ખાલી) {
					result = ERRSET_NOMEMORY;
					જાઓ fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	પાછા (ERRSET_SUCCESS);

fail:
	જો (rrset != ખાલી)
		freerrset(rrset);
	જો (response != ખાલી)
		free_dns_response(response);
	પાછા (result);
}

શૂન્ય
freerrset(સંરચના rrsetinfo *rrset)
{
	u_int16_t i;

	જો (rrset == ખાલી)
		પાછા;

	જો (rrset->rri_rdatas) {
		માટે (i = 0; i < rrset->rri_nrdatas; i++) {
			જો (rrset->rri_rdatas[i].rdi_data == ખાલી)
				તોડો;
			મુક્ત(rrset->rri_rdatas[i].rdi_data);
		}
		મુક્ત(rrset->rri_rdatas);
	}

	જો (rrset->rri_sigs) {
		માટે (i = 0; i < rrset->rri_nsigs; i++) {
			જો (rrset->rri_sigs[i].rdi_data == ખાલી)
				તોડો;
			મુક્ત(rrset->rri_sigs[i].rdi_data);
		}
		મુક્ત(rrset->rri_sigs);
	}

	જો (rrset->rri_name)
		મુક્ત(rrset->rri_name);
	મુક્ત(rrset);
}

/*
 * DNS response parsing routines
 */
સ્થિર સંરચના dns_response *
parse_dns_response(અચલ u_char *answer, પૂર્ણાંક size)
{
	સંરચના dns_response *resp;
	અચલ u_char *cp;

	જો (size < HFIXEDSZ)
		પાછા (ખાલી);

	/* allocate memory for the response */
	resp = calloc(1, કદ(*resp));
	જો (resp == ખાલી)
		પાછા (ખાલી);

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
	જો (resp->header.qdcount < 1) {
		free_dns_response(resp);
		પાછા (ખાલી);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	જો (resp->header.qdcount && resp->query == ખાલી) {
		free_dns_response(resp);
		પાછા (ખાલી);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	જો (resp->header.ancount && resp->answer == ખાલી) {
		free_dns_response(resp);
		પાછા (ખાલી);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	જો (resp->header.nscount && resp->authority == ખાલી) {
		free_dns_response(resp);
		પાછા (ખાલી);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	જો (resp->header.arcount && resp->additional == ખાલી) {
		free_dns_response(resp);
		પાછા (ખાલી);
	}

	પાછા (resp);
}

સ્થિર સંરચના dns_query *
parse_dns_qsection(અચલ u_char *answer, પૂર્ણાંક size, અચલ u_char **cp, પૂર્ણાંક ગણતરી)
{
	સંરચના dns_query *head, *curr, *prev;
	પૂર્ણાંક i, length;
	અક્ષર name[MAXDNAME];

#define NEED(need) \
	કરો { \
		જો (*cp + need > answer + size) \
			જાઓ fail; \
	} જ્યારે (0)

	માટે (i = 1, head = ખાલી, prev = ખાલી; i <= ગણતરી; i++, prev = curr) {
		જો (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			પાછા (ખાલી);
		}
		/* allocate and initialize struct */
		curr = calloc(1, કદ(સંરચના dns_query));
		જો (curr == ખાલી)
			જાઓ fail;
		જો (head == ખાલી)
			head = curr;
		જો (prev != ખાલી)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    કદ(name));
		જો (length < 0) {
			free_dns_query(head);
			પાછા (ખાલી);
		}
		curr->name = strdup(name);
		જો (curr->name == ખાલી) {
			free_dns_query(head);
			પાછા (ખાલી);
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

	પાછા (head);
}

સ્થિર સંરચના dns_rr *
parse_dns_rrsection(અચલ u_char *answer, પૂર્ણાંક size, અચલ u_char **cp,
    પૂર્ણાંક ગણતરી)
{
	સંરચના dns_rr *head, *curr, *prev;
	પૂર્ણાંક i, length;
	અક્ષર name[MAXDNAME];

#define NEED(need) \
	કરો { \
		જો (*cp + need > answer + size) \
			જાઓ fail; \
	} જ્યારે (0)

	માટે (i = 1, head = ખાલી, prev = ખાલી; i <= ગણતરી; i++, prev = curr) {
		જો (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			પાછા (ખાલી);
		}

		/* allocate and initialize struct */
		curr = calloc(1, કદ(સંરચના dns_rr));
		જો (curr == ખાલી)
			જાઓ fail;
		જો (head == ખાલી)
			head = curr;
		જો (prev != ખાલી)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    કદ(name));
		જો (length < 0) {
			free_dns_rr(head);
			પાછા (ખાલી);
		}
		curr->name = strdup(name);
		જો (curr->name == ખાલી) {
			free_dns_rr(head);
			પાછા (ખાલી);
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
		જો (curr->size != 0) {
			જો ((curr->rdata = malloc(curr->size)) == ખાલી) {
				free_dns_rr(head);
				પાછા (ખાલી);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	પાછા (head);
}

સ્થિર શૂન્ય
free_dns_query(સંરચના dns_query *p)
{
	સંરચના dns_query *next;

	જ્યારે (p != ખાલી) {
		next = p->next;
		મુક્ત(p->name);
		મુક્ત(p);
		p = next;
	}
}

સ્થિર શૂન્ય
free_dns_rr(સંરચના dns_rr *p)
{
	સંરચના dns_rr *next;

	જ્યારે (p != ખાલી) {
		next = p->next;
		મુક્ત(p->name);
		મુક્ત(p->rdata);
		મુક્ત(p);
		p = next;
	}
}

સ્થિર શૂન્ય
free_dns_response(સંરચના dns_response *p)
{
	જો (p == ખાલી)
		પાછા;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	મુક્ત(p);
}

સ્થિર પૂર્ણાંક
ગણતરી_dns_rr(સંરચના dns_rr *p, u_int16_t class, u_int16_t type)
{
	પૂર્ણાંક n = 0;

	જ્યારે(p) {
		જો (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	પાછા (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
