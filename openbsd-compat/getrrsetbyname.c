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

#ಯದಿ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ "getrrsetbyname.h"

#ಯದಿ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
ಸಂರಚನಾ __res_state _res;
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
#ಯದಿ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
_getshort(ಧ್ರುವ u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ಪ್ರತ್ಯಾಗಮ (u);
}

ಸ್ಥಿರ u_int32_t
_getlong(ಧ್ರುವ u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ಪ್ರತ್ಯಾಗಮ (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

ಸಂರಚನಾ dns_query {
	ವರ್ಣ			*name;
	u_int16_t		type;
	u_int16_t		class;
	ಸಂರಚನಾ dns_query	*next;
};

ಸಂರಚನಾ dns_rr {
	ವರ್ಣ			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	ಶೂನ್ಯ			*rdata;
	ಸಂರಚನಾ dns_rr		*next;
};

ಸಂರಚನಾ dns_response {
	HEADER			header;
	ಸಂರಚನಾ dns_query	*query;
	ಸಂರಚನಾ dns_rr		*answer;
	ಸಂರಚನಾ dns_rr		*authority;
	ಸಂರಚನಾ dns_rr		*additional;
};

ಸ್ಥಿರ ಸಂರಚನಾ dns_response *parse_dns_response(ಧ್ರುವ u_char *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಸಂರಚನಾ dns_query *parse_dns_qsection(ಧ್ರುವ u_char *, ಪೂರ್ಣಾಙ್ಕ,
    ಧ್ರುವ u_char **, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಸಂರಚನಾ dns_rr *parse_dns_rrsection(ಧ್ರುವ u_char *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ u_char **,
    ಪೂರ್ಣಾಙ್ಕ);

ಸ್ಥಿರ ಶೂನ್ಯ free_dns_query(ಸಂರಚನಾ dns_query *);
ಸ್ಥಿರ ಶೂನ್ಯ free_dns_rr(ಸಂರಚನಾ dns_rr *);
ಸ್ಥಿರ ಶೂನ್ಯ free_dns_response(ಸಂರಚನಾ dns_response *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ_dns_rr(ಸಂರಚನಾ dns_rr *, u_int16_t, u_int16_t);

ಪೂರ್ಣಾಙ್ಕ
getrrsetbyname(ಧ್ರುವ ವರ್ಣ *hostname, unsigned ಪೂರ್ಣಾಙ್ಕ rdclass,
    unsigned ಪೂರ್ಣಾಙ್ಕ rdtype, unsigned ಪೂರ್ಣಾಙ್ಕ flags,
    ಸಂರಚನಾ rrsetinfo **res)
{
	ಸಂರಚನಾ __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	ಪೂರ್ಣಾಙ್ಕ result;
	ಸಂರಚನಾ rrsetinfo *rrset = ರಿಕ್ತ;
	ಸಂರಚನಾ dns_response *response = ರಿಕ್ತ;
	ಸಂರಚನಾ dns_rr *rr;
	ಸಂರಚನಾ rdatainfo *rdata;
	ಪೂರ್ಣಾಙ್ಕ length;
	unsigned ಪೂರ್ಣಾಙ್ಕ index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	ಯದಿ (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		ಗಚ್ಛ fail;
	}

	/* don't allow queries of class or type ANY */
	ಯದಿ (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		ಗಚ್ಛ fail;
	}

	/* don't allow flags yet, unimplemented */
	ಯದಿ (flags) {
		result = ERRSET_INVAL;
		ಗಚ್ಛ fail;
	}

	/* initialize resolver */
	ಯದಿ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		ಗಚ್ಛ fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ಯದಿ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed ಪೂರ್ಣಾಙ್ಕ) rdclass, (signed ಪೂರ್ಣಾಙ್ಕ) rdtype,
	    answer, ಪರಿಮಾಣ(answer));
	ಯದಿ (length < 0) {
		ವಿಕಲ್ಪ(h_errno) {
		ಪಕ್ಷ HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			ಗಚ್ಛ fail;
		ಪಕ್ಷ NO_DATA:
			result = ERRSET_NODATA;
			ಗಚ್ಛ fail;
		ಸ್ವಭಾವ:
			result = ERRSET_FAIL;
			ಗಚ್ಛ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	ಯದಿ (response == ರಿಕ್ತ) {
		result = ERRSET_FAIL;
		ಗಚ್ಛ fail;
	}

	ಯದಿ (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		ಗಚ್ಛ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, ಪರಿಮಾಣ(ಸಂರಚನಾ rrsetinfo));
	ಯದಿ (rrset == ರಿಕ್ತ) {
		result = ERRSET_NOMEMORY;
		ಗಚ್ಛ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	ಯದಿ (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ಯದಿ (rrset->rri_name == ರಿಕ್ತ) {
		result = ERRSET_NOMEMORY;
		ಗಚ್ಛ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ಎಣಿಕೆ_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ಎಣಿಕೆ_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    ಪರಿಮಾಣ(ಸಂರಚನಾ rdatainfo));
	ಯದಿ (rrset->rri_rdatas == ರಿಕ್ತ) {
		result = ERRSET_NOMEMORY;
		ಗಚ್ಛ fail;
	}

	/* allocate memory for signatures */
	ಯದಿ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, ಪರಿಮಾಣ(ಸಂರಚನಾ rdatainfo));
		ಯದಿ (rrset->rri_sigs == ರಿಕ್ತ) {
			result = ERRSET_NOMEMORY;
			ಗಚ್ಛ fail;
		}
	}

	/* copy answers & signatures */
	ಪ್ರತಿ (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = ರಿಕ್ತ;

		ಯದಿ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		ಯದಿ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		ಯದಿ (rdata) {
			rdata->rdi_length = rr->size;
			ಯದಿ (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				ಯದಿ (rdata->rdi_data == ರಿಕ್ತ) {
					result = ERRSET_NOMEMORY;
					ಗಚ್ಛ fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ಪ್ರತ್ಯಾಗಮ (ERRSET_SUCCESS);

fail:
	ಯದಿ (rrset != ರಿಕ್ತ)
		freerrset(rrset);
	ಯದಿ (response != ರಿಕ್ತ)
		free_dns_response(response);
	ಪ್ರತ್ಯಾಗಮ (result);
}

ಶೂನ್ಯ
freerrset(ಸಂರಚನಾ rrsetinfo *rrset)
{
	u_int16_t i;

	ಯದಿ (rrset == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (rrset->rri_rdatas) {
		ಪ್ರತಿ (i = 0; i < rrset->rri_nrdatas; i++) {
			ಯದಿ (rrset->rri_rdatas[i].rdi_data == ರಿಕ್ತ)
				ಭಙ್ಗ;
			ಮುಕ್ತ(rrset->rri_rdatas[i].rdi_data);
		}
		ಮುಕ್ತ(rrset->rri_rdatas);
	}

	ಯದಿ (rrset->rri_sigs) {
		ಪ್ರತಿ (i = 0; i < rrset->rri_nsigs; i++) {
			ಯದಿ (rrset->rri_sigs[i].rdi_data == ರಿಕ್ತ)
				ಭಙ್ಗ;
			ಮುಕ್ತ(rrset->rri_sigs[i].rdi_data);
		}
		ಮುಕ್ತ(rrset->rri_sigs);
	}

	ಯದಿ (rrset->rri_name)
		ಮುಕ್ತ(rrset->rri_name);
	ಮುಕ್ತ(rrset);
}

/*
 * DNS response parsing routines
 */
ಸ್ಥಿರ ಸಂರಚನಾ dns_response *
parse_dns_response(ಧ್ರುವ u_char *answer, ಪೂರ್ಣಾಙ್ಕ size)
{
	ಸಂರಚನಾ dns_response *resp;
	ಧ್ರುವ u_char *cp;

	ಯದಿ (size < HFIXEDSZ)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

	/* allocate memory for the response */
	resp = calloc(1, ಪರಿಮಾಣ(*resp));
	ಯದಿ (resp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);

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
	ಯದಿ (resp->header.qdcount < 1) {
		free_dns_response(resp);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	ಯದಿ (resp->header.qdcount && resp->query == ರಿಕ್ತ) {
		free_dns_response(resp);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	ಯದಿ (resp->header.ancount && resp->answer == ರಿಕ್ತ) {
		free_dns_response(resp);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	ಯದಿ (resp->header.nscount && resp->authority == ರಿಕ್ತ) {
		free_dns_response(resp);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	ಯದಿ (resp->header.arcount && resp->additional == ರಿಕ್ತ) {
		free_dns_response(resp);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	ಪ್ರತ್ಯಾಗಮ (resp);
}

ಸ್ಥಿರ ಸಂರಚನಾ dns_query *
parse_dns_qsection(ಧ್ರುವ u_char *answer, ಪೂರ್ಣಾಙ್ಕ size, ಧ್ರುವ u_char **cp, ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ)
{
	ಸಂರಚನಾ dns_query *head, *curr, *prev;
	ಪೂರ್ಣಾಙ್ಕ i, length;
	ವರ್ಣ name[MAXDNAME];

#define NEED(need) \
	ಕುರು { \
		ಯದಿ (*cp + need > answer + size) \
			ಗಚ್ಛ fail; \
	} ಯಾವತ್ (0)

	ಪ್ರತಿ (i = 1, head = ರಿಕ್ತ, prev = ರಿಕ್ತ; i <= ಎಣಿಕೆ; i++, prev = curr) {
		ಯದಿ (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}
		/* allocate and initialize struct */
		curr = calloc(1, ಪರಿಮಾಣ(ಸಂರಚನಾ dns_query));
		ಯದಿ (curr == ರಿಕ್ತ)
			ಗಚ್ಛ fail;
		ಯದಿ (head == ರಿಕ್ತ)
			head = curr;
		ಯದಿ (prev != ರಿಕ್ತ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    ಪರಿಮಾಣ(name));
		ಯದಿ (length < 0) {
			free_dns_query(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}
		curr->name = strdup(name);
		ಯದಿ (curr->name == ರಿಕ್ತ) {
			free_dns_query(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
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

	ಪ್ರತ್ಯಾಗಮ (head);
}

ಸ್ಥಿರ ಸಂರಚನಾ dns_rr *
parse_dns_rrsection(ಧ್ರುವ u_char *answer, ಪೂರ್ಣಾಙ್ಕ size, ಧ್ರುವ u_char **cp,
    ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ)
{
	ಸಂರಚನಾ dns_rr *head, *curr, *prev;
	ಪೂರ್ಣಾಙ್ಕ i, length;
	ವರ್ಣ name[MAXDNAME];

#define NEED(need) \
	ಕುರು { \
		ಯದಿ (*cp + need > answer + size) \
			ಗಚ್ಛ fail; \
	} ಯಾವತ್ (0)

	ಪ್ರತಿ (i = 1, head = ರಿಕ್ತ, prev = ರಿಕ್ತ; i <= ಎಣಿಕೆ; i++, prev = curr) {
		ಯದಿ (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}

		/* allocate and initialize struct */
		curr = calloc(1, ಪರಿಮಾಣ(ಸಂರಚನಾ dns_rr));
		ಯದಿ (curr == ರಿಕ್ತ)
			ಗಚ್ಛ fail;
		ಯದಿ (head == ರಿಕ್ತ)
			head = curr;
		ಯದಿ (prev != ರಿಕ್ತ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    ಪರಿಮಾಣ(name));
		ಯದಿ (length < 0) {
			free_dns_rr(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}
		curr->name = strdup(name);
		ಯದಿ (curr->name == ರಿಕ್ತ) {
			free_dns_rr(head);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
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
		ಯದಿ (curr->size != 0) {
			ಯದಿ ((curr->rdata = malloc(curr->size)) == ರಿಕ್ತ) {
				free_dns_rr(head);
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	ಪ್ರತ್ಯಾಗಮ (head);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_query(ಸಂರಚನಾ dns_query *p)
{
	ಸಂರಚನಾ dns_query *next;

	ಯಾವತ್ (p != ರಿಕ್ತ) {
		next = p->next;
		ಮುಕ್ತ(p->name);
		ಮುಕ್ತ(p);
		p = next;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_rr(ಸಂರಚನಾ dns_rr *p)
{
	ಸಂರಚನಾ dns_rr *next;

	ಯಾವತ್ (p != ರಿಕ್ತ) {
		next = p->next;
		ಮುಕ್ತ(p->name);
		ಮುಕ್ತ(p->rdata);
		ಮುಕ್ತ(p);
		p = next;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dns_response(ಸಂರಚನಾ dns_response *p)
{
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	ಮುಕ್ತ(p);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಎಣಿಕೆ_dns_rr(ಸಂರಚನಾ dns_rr *p, u_int16_t class, u_int16_t type)
{
	ಪೂರ್ಣಾಙ್ಕ n = 0;

	ಯಾವತ್(p) {
		ಯದಿ (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	ಪ್ರತ್ಯಾಗಮ (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
