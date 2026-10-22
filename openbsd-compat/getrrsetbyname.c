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

#ако !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "getrrsetbyname.h"

#ако defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
extern цяло h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
struct __res_state _res;
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
#ако !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
	върни (u);
}

static u_int32_t
_getlong(const u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	върни (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

struct dns_query {
	char			*name;
	u_int16_t		type;
	u_int16_t		class;
	struct dns_query	*next;
};

struct dns_rr {
	char			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	void			*rdata;
	struct dns_rr		*next;
};

struct dns_response {
	HEADER			header;
	struct dns_query	*query;
	struct dns_rr		*answer;
	struct dns_rr		*authority;
	struct dns_rr		*additional;
};

static struct dns_response *parse_dns_response(const u_char *, цяло);
static struct dns_query *parse_dns_qsection(const u_char *, цяло,
    const u_char **, цяло);
static struct dns_rr *parse_dns_rrsection(const u_char *, цяло, const u_char **,
    цяло);

static void free_dns_query(struct dns_query *);
static void free_dns_rr(struct dns_rr *);
static void free_dns_response(struct dns_response *);

static цяло count_dns_rr(struct dns_rr *, u_int16_t, u_int16_t);

цяло
getrrsetbyname(const char *hostname, unsigned цяло rdclass,
    unsigned цяло rdtype, unsigned цяло flags,
    struct rrsetinfo **res)
{
	struct __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	цяло result;
	struct rrsetinfo *rrset = NULL;
	struct dns_response *response = NULL;
	struct dns_rr *rr;
	struct rdatainfo *rdata;
	цяло length;
	unsigned цяло index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	ако (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* don't allow queries of class or type ANY */
	ако (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* don't allow flags yet, unimplemented */
	ако (flags) {
		result = ERRSET_INVAL;
		goto fail;
	}

	/* initialize resolver */
	ако ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		goto fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ако (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed цяло) rdclass, (signed цяло) rdtype,
	    answer, sizeof(answer));
	ако (length < 0) {
		switch(h_errno) {
		case HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			goto fail;
		case NO_DATA:
			result = ERRSET_NODATA;
			goto fail;
		default:
			result = ERRSET_FAIL;
			goto fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	ако (response == NULL) {
		result = ERRSET_FAIL;
		goto fail;
	}

	ако (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		goto fail;
	}

	/* initialize rrset */
	rrset = calloc(1, sizeof(struct rrsetinfo));
	ако (rrset == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	ако (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ако (rrset->rri_name == NULL) {
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
	    sizeof(struct rdatainfo));
	ако (rrset->rri_rdatas == NULL) {
		result = ERRSET_NOMEMORY;
		goto fail;
	}

	/* allocate memory for signatures */
	ако (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, sizeof(struct rdatainfo));
		ако (rrset->rri_sigs == NULL) {
			result = ERRSET_NOMEMORY;
			goto fail;
		}
	}

	/* copy answers & signatures */
	за (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = NULL;

		ако (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		ако (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		ако (rdata) {
			rdata->rdi_length = rr->size;
			ако (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				ако (rdata->rdi_data == NULL) {
					result = ERRSET_NOMEMORY;
					goto fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	върни (ERRSET_SUCCESS);

fail:
	ако (rrset != NULL)
		freerrset(rrset);
	ако (response != NULL)
		free_dns_response(response);
	върни (result);
}

void
freerrset(struct rrsetinfo *rrset)
{
	u_int16_t i;

	ако (rrset == NULL)
		върни;

	ако (rrset->rri_rdatas) {
		за (i = 0; i < rrset->rri_nrdatas; i++) {
			ако (rrset->rri_rdatas[i].rdi_data == NULL)
				break;
			free(rrset->rri_rdatas[i].rdi_data);
		}
		free(rrset->rri_rdatas);
	}

	ако (rrset->rri_sigs) {
		за (i = 0; i < rrset->rri_nsigs; i++) {
			ако (rrset->rri_sigs[i].rdi_data == NULL)
				break;
			free(rrset->rri_sigs[i].rdi_data);
		}
		free(rrset->rri_sigs);
	}

	ако (rrset->rri_name)
		free(rrset->rri_name);
	free(rrset);
}

/*
 * DNS response parsing routines
 */
static struct dns_response *
parse_dns_response(const u_char *answer, цяло size)
{
	struct dns_response *resp;
	const u_char *cp;

	ако (size < HFIXEDSZ)
		върни (NULL);

	/* allocate memory for the response */
	resp = calloc(1, sizeof(*resp));
	ако (resp == NULL)
		върни (NULL);

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
	ако (resp->header.qdcount < 1) {
		free_dns_response(resp);
		върни (NULL);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	ако (resp->header.qdcount && resp->query == NULL) {
		free_dns_response(resp);
		върни (NULL);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	ако (resp->header.ancount && resp->answer == NULL) {
		free_dns_response(resp);
		върни (NULL);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	ако (resp->header.nscount && resp->authority == NULL) {
		free_dns_response(resp);
		върни (NULL);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	ако (resp->header.arcount && resp->additional == NULL) {
		free_dns_response(resp);
		върни (NULL);
	}

	върни (resp);
}

static struct dns_query *
parse_dns_qsection(const u_char *answer, цяло size, const u_char **cp, цяло count)
{
	struct dns_query *head, *curr, *prev;
	цяло i, length;
	char name[MAXDNAME];

#define NEED(need) \
	do { \
		ако (*cp + need > answer + size) \
			goto fail; \
	} докато (0)

	за (i = 1, head = NULL, prev = NULL; i <= count; i++, prev = curr) {
		ако (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			върни (NULL);
		}
		/* allocate and initialize struct */
		curr = calloc(1, sizeof(struct dns_query));
		ако (curr == NULL)
			goto fail;
		ако (head == NULL)
			head = curr;
		ако (prev != NULL)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    sizeof(name));
		ако (length < 0) {
			free_dns_query(head);
			върни (NULL);
		}
		curr->name = strdup(name);
		ако (curr->name == NULL) {
			free_dns_query(head);
			върни (NULL);
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

	върни (head);
}

static struct dns_rr *
parse_dns_rrsection(const u_char *answer, цяло size, const u_char **cp,
    цяло count)
{
	struct dns_rr *head, *curr, *prev;
	цяло i, length;
	char name[MAXDNAME];

#define NEED(need) \
	do { \
		ако (*cp + need > answer + size) \
			goto fail; \
	} докато (0)

	за (i = 1, head = NULL, prev = NULL; i <= count; i++, prev = curr) {
		ако (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			върни (NULL);
		}

		/* allocate and initialize struct */
		curr = calloc(1, sizeof(struct dns_rr));
		ако (curr == NULL)
			goto fail;
		ако (head == NULL)
			head = curr;
		ако (prev != NULL)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    sizeof(name));
		ако (length < 0) {
			free_dns_rr(head);
			върни (NULL);
		}
		curr->name = strdup(name);
		ако (curr->name == NULL) {
			free_dns_rr(head);
			върни (NULL);
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
		ако (curr->size != 0) {
			ако ((curr->rdata = malloc(curr->size)) == NULL) {
				free_dns_rr(head);
				върни (NULL);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	върни (head);
}

static void
free_dns_query(struct dns_query *p)
{
	struct dns_query *next;

	докато (p != NULL) {
		next = p->next;
		free(p->name);
		free(p);
		p = next;
	}
}

static void
free_dns_rr(struct dns_rr *p)
{
	struct dns_rr *next;

	докато (p != NULL) {
		next = p->next;
		free(p->name);
		free(p->rdata);
		free(p);
		p = next;
	}
}

static void
free_dns_response(struct dns_response *p)
{
	ако (p == NULL)
		върни;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	free(p);
}

static цяло
count_dns_rr(struct dns_rr *p, u_int16_t class, u_int16_t type)
{
	цяло n = 0;

	докато(p) {
		ако (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	върни (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
