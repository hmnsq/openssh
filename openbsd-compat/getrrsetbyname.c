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

#include "includes.h"

#ꦪꦼꦤ꧀ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "getrrsetbyname.h"

#ꦪꦼꦤ꧀ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
extern puur_naa_nka h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
sa_nracanaa __res_state _res;
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
#ꦪꦼꦤ꧀ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
static u_int16_t
_getshort(const u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ꦮꦭꦶ (u);
}

static u_int32_t
_getlong(const u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ꦮꦭꦶ (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

sa_nracanaa dns_query {
	var_na			*name;
	u_int16_t		type;
	u_int16_t		class;
	sa_nracanaa dns_query	*next;
};

sa_nracanaa dns_rr {
	var_na			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	void			*rdata;
	sa_nracanaa dns_rr		*next;
};

sa_nracanaa dns_response {
	HEADER			header;
	sa_nracanaa dns_query	*query;
	sa_nracanaa dns_rr		*answer;
	sa_nracanaa dns_rr		*authority;
	sa_nracanaa dns_rr		*additional;
};

static sa_nracanaa dns_response *parse_dns_response(const u_char *, puur_naa_nka);
static sa_nracanaa dns_query *parse_dns_qsection(const u_char *, puur_naa_nka,
    const u_char **, puur_naa_nka);
static sa_nracanaa dns_rr *parse_dns_rrsection(const u_char *, puur_naa_nka, const u_char **,
    puur_naa_nka);

static void free_dns_query(sa_nracanaa dns_query *);
static void free_dns_rr(sa_nracanaa dns_rr *);
static void free_dns_response(sa_nracanaa dns_response *);

static puur_naa_nka count_dns_rr(sa_nracanaa dns_rr *, u_int16_t, u_int16_t);

puur_naa_nka
getrrsetbyname(const var_na *hostname, unsigned puur_naa_nka rdclass,
    unsigned puur_naa_nka rdtype, unsigned puur_naa_nka flags,
    sa_nracanaa rrsetinfo **res)
{
	sa_nracanaa __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	puur_naa_nka result;
	sa_nracanaa rrsetinfo *rrset = NULL;
	sa_nracanaa dns_response *response = NULL;
	sa_nracanaa dns_rr *rr;
	sa_nracanaa rdatainfo *rdata;
	puur_naa_nka length;
	unsigned puur_naa_nka index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	ꦪꦼꦤ꧀ (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* don't allow queries of class or type ANY */
	ꦪꦼꦤ꧀ (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* don't allow flags yet, unimplemented */
	ꦪꦼꦤ꧀ (flags) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* initialize resolver */
	ꦪꦼꦤ꧀ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		goto fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ꦪꦼꦤ꧀ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed puur_naa_nka) rdclass, (signed puur_naa_nka) rdtype,
	    answer, parimaa_na(answer));
	ꦪꦼꦤ꧀ (length < 0) {
		switch(h_errno) {
		pak_sa HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			goto fail;
		pak_sa NO_DATA:
			result = ERRSET_NODATA;
			goto fail;
		default:
			result = ERRSET_FAIL;
			goto fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	ꦪꦼꦤ꧀ (response == NULL) {
		result = ERRSET_FAIL;
		goto fail;
	}

	ꦪꦼꦤ꧀ (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		goto fail;
	}

	/* initialize rrset */
	rrset = calloc(1, parimaa_na(sa_nracanaa rrsetinfo));
	ꦪꦼꦤ꧀ (rrset == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	ꦪꦼꦤ꧀ (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ꦪꦼꦤ꧀ (rrset->rri_name == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}

	/* count answers */
	rrset->rri_nrdatas = count_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = count_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    parimaa_na(sa_nracanaa rdatainfo));
	ꦪꦼꦤ꧀ (rrset->rri_rdatas == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}

	/* allocate memory for signatures */
	ꦪꦼꦤ꧀ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, parimaa_na(sa_nracanaa rdatainfo));
		ꦪꦼꦤ꧀ (rrset->rri_sigs == NULL) {
			result = ERRSET_NOMEMORY;
			goto fail;
		}
	}

	/* copy answers & signatures */
	ꦏꦁꦒꦺꦴ (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = NULL;

		ꦪꦼꦤ꧀ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		ꦪꦼꦤ꧀ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		ꦪꦼꦤ꧀ (rdata) {
			rdata->rdi_length = rr->size;
			ꦪꦼꦤ꧀ (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				ꦪꦼꦤ꧀ (rdata->rdi_data == NULL) {
					result = ERRSET_NOMEMORY;
					goto fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ꦮꦭꦶ (ERRSET_SUCCESS);

fail:
	ꦪꦼꦤ꧀ (rrset != NULL)
		freerrset(rrset);
	ꦪꦼꦤ꧀ (response != NULL)
		free_dns_response(response);
	ꦮꦭꦶ (result);
}

void
freerrset(sa_nracanaa rrsetinfo *rrset)
{
	u_int16_t i;

	ꦪꦼꦤ꧀ (rrset == NULL)
		ꦮꦭꦶ;

	ꦪꦼꦤ꧀ (rrset->rri_rdatas) {
		ꦏꦁꦒꦺꦴ (i = 0; i < rrset->rri_nrdatas; i++) {
			ꦪꦼꦤ꧀ (rrset->rri_rdatas[i].rdi_data == NULL)
				bha_nga;
			free(rrset->rri_rdatas[i].rdi_data);
		}
		free(rrset->rri_rdatas);
	}

	ꦪꦼꦤ꧀ (rrset->rri_sigs) {
		ꦏꦁꦒꦺꦴ (i = 0; i < rrset->rri_nsigs; i++) {
			ꦪꦼꦤ꧀ (rrset->rri_sigs[i].rdi_data == NULL)
				bha_nga;
			free(rrset->rri_sigs[i].rdi_data);
		}
		free(rrset->rri_sigs);
	}

	ꦪꦼꦤ꧀ (rrset->rri_name)
		free(rrset->rri_name);
	free(rrset);
}

/*
 * DNS response parsing routines
 */
static sa_nracanaa dns_response *
parse_dns_response(const u_char *answer, puur_naa_nka size)
{
	sa_nracanaa dns_response *resp;
	const u_char *cp;

	ꦪꦼꦤ꧀ (size < HFIXEDSZ)
		ꦮꦭꦶ (NULL);

	/* allocate memory for the response */
	resp = calloc(1, parimaa_na(*resp));
	ꦪꦼꦤ꧀ (resp == NULL)
		ꦮꦭꦶ (NULL);

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
	ꦪꦼꦤ꧀ (resp->header.qdcount < 1) {
		free_dns_response(resp);
		ꦮꦭꦶ (NULL);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	ꦪꦼꦤ꧀ (resp->header.qdcount && resp->query == NULL) {
		free_dns_response(resp);
		ꦮꦭꦶ (NULL);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	ꦪꦼꦤ꧀ (resp->header.ancount && resp->answer == NULL) {
		free_dns_response(resp);
		ꦮꦭꦶ (NULL);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	ꦪꦼꦤ꧀ (resp->header.nscount && resp->authority == NULL) {
		free_dns_response(resp);
		ꦮꦭꦶ (NULL);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	ꦪꦼꦤ꧀ (resp->header.arcount && resp->additional == NULL) {
		free_dns_response(resp);
		ꦮꦭꦶ (NULL);
	}

	ꦮꦭꦶ (resp);
}

static sa_nracanaa dns_query *
parse_dns_qsection(const u_char *answer, puur_naa_nka size, const u_char **cp, puur_naa_nka count)
{
	sa_nracanaa dns_query *head, *curr, *prev;
	puur_naa_nka i, length;
	var_na name[MAXDNAME];

#define NEED(need) \
	do { \
		ꦪꦼꦤ꧀ (*cp + need > answer + size) \
			goto fail; \
	} ꦱꦼꦢꦼꦭ (0)

	ꦏꦁꦒꦺꦴ (i = 1, head = NULL, prev = NULL; i <= count; i++, prev = curr) {
		ꦪꦼꦤ꧀ (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			ꦮꦭꦶ (NULL);
		}
		/* allocate and initialize struct */
		curr = calloc(1, parimaa_na(sa_nracanaa dns_query));
		ꦪꦼꦤ꧀ (curr == NULL)
			goto fail;
		ꦪꦼꦤ꧀ (head == NULL)
			head = curr;
		ꦪꦼꦤ꧀ (prev != NULL)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    parimaa_na(name));
		ꦪꦼꦤ꧀ (length < 0) {
			free_dns_query(head);
			ꦮꦭꦶ (NULL);
		}
		curr->name = strdup(name);
		ꦪꦼꦤ꧀ (curr->name == NULL) {
			free_dns_query(head);
			ꦮꦭꦶ (NULL);
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

	ꦮꦭꦶ (head);
}

static sa_nracanaa dns_rr *
parse_dns_rrsection(const u_char *answer, puur_naa_nka size, const u_char **cp,
    puur_naa_nka count)
{
	sa_nracanaa dns_rr *head, *curr, *prev;
	puur_naa_nka i, length;
	var_na name[MAXDNAME];

#define NEED(need) \
	do { \
		ꦪꦼꦤ꧀ (*cp + need > answer + size) \
			goto fail; \
	} ꦱꦼꦢꦼꦭ (0)

	ꦏꦁꦒꦺꦴ (i = 1, head = NULL, prev = NULL; i <= count; i++, prev = curr) {
		ꦪꦼꦤ꧀ (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			ꦮꦭꦶ (NULL);
		}

		/* allocate and initialize struct */
		curr = calloc(1, parimaa_na(sa_nracanaa dns_rr));
		ꦪꦼꦤ꧀ (curr == NULL)
			goto fail;
		ꦪꦼꦤ꧀ (head == NULL)
			head = curr;
		ꦪꦼꦤ꧀ (prev != NULL)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    parimaa_na(name));
		ꦪꦼꦤ꧀ (length < 0) {
			free_dns_rr(head);
			ꦮꦭꦶ (NULL);
		}
		curr->name = strdup(name);
		ꦪꦼꦤ꧀ (curr->name == NULL) {
			free_dns_rr(head);
			ꦮꦭꦶ (NULL);
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
		ꦪꦼꦤ꧀ (curr->size != 0) {
			ꦪꦼꦤ꧀ ((curr->rdata = malloc(curr->size)) == NULL) {
				free_dns_rr(head);
				ꦮꦭꦶ (NULL);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	ꦮꦭꦶ (head);
}

static void
free_dns_query(sa_nracanaa dns_query *p)
{
	sa_nracanaa dns_query *next;

	ꦱꦼꦢꦼꦭ (p != NULL) {
		next = p->next;
		free(p->name);
		free(p);
		p = next;
	}
}

static void
free_dns_rr(sa_nracanaa dns_rr *p)
{
	sa_nracanaa dns_rr *next;

	ꦱꦼꦢꦼꦭ (p != NULL) {
		next = p->next;
		free(p->name);
		free(p->rdata);
		free(p);
		p = next;
	}
}

static void
free_dns_response(sa_nracanaa dns_response *p)
{
	ꦪꦼꦤ꧀ (p == NULL)
		ꦮꦭꦶ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	free(p);
}

static puur_naa_nka
count_dns_rr(sa_nracanaa dns_rr *p, u_int16_t class, u_int16_t type)
{
	puur_naa_nka n = 0;

	ꦱꦼꦢꦼꦭ(p) {
		ꦪꦼꦤ꧀ (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	ꦮꦭꦶ (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
