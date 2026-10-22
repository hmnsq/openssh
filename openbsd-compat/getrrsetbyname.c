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

#अन्तर्भाव "includes.h"

#यदि !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव "getrrsetbyname.h"

#यदि defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
बाह्य पूर्णाङ्क h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
संरचना __res_state _res;
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
#यदि !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
स्थिर u_int16_t
_getshort(ध्रुव u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	प्रत्यागम (u);
}

स्थिर u_int32_t
_getlong(ध्रुव u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	प्रत्यागम (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

संरचना dns_query {
	वर्ण			*name;
	u_int16_t		type;
	u_int16_t		class;
	संरचना dns_query	*next;
};

संरचना dns_rr {
	वर्ण			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	शून्य			*rdata;
	संरचना dns_rr		*next;
};

संरचना dns_response {
	HEADER			header;
	संरचना dns_query	*query;
	संरचना dns_rr		*answer;
	संरचना dns_rr		*authority;
	संरचना dns_rr		*additional;
};

स्थिर संरचना dns_response *parse_dns_response(ध्रुव u_char *, पूर्णाङ्क);
स्थिर संरचना dns_query *parse_dns_qsection(ध्रुव u_char *, पूर्णाङ्क,
    ध्रुव u_char **, पूर्णाङ्क);
स्थिर संरचना dns_rr *parse_dns_rrsection(ध्रुव u_char *, पूर्णाङ्क, ध्रुव u_char **,
    पूर्णाङ्क);

स्थिर शून्य free_dns_query(संरचना dns_query *);
स्थिर शून्य free_dns_rr(संरचना dns_rr *);
स्थिर शून्य free_dns_response(संरचना dns_response *);

स्थिर पूर्णाङ्क मोजणी_dns_rr(संरचना dns_rr *, u_int16_t, u_int16_t);

पूर्णाङ्क
getrrsetbyname(ध्रुव वर्ण *hostname, unsigned पूर्णाङ्क rdclass,
    unsigned पूर्णाङ्क rdtype, unsigned पूर्णाङ्क flags,
    संरचना rrsetinfo **res)
{
	संरचना __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	पूर्णाङ्क result;
	संरचना rrsetinfo *rrset = रिक्त;
	संरचना dns_response *response = रिक्त;
	संरचना dns_rr *rr;
	संरचना rdatainfo *rdata;
	पूर्णाङ्क length;
	unsigned पूर्णाङ्क index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	यदि (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow queries of class or type ANY */
	यदि (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow flags yet, unimplemented */
	यदि (flags) {
		result = ERRSET_INVAL;
		गच्छ fail;
	}

	/* initialize resolver */
	यदि ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		गच्छ fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	यदि (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed पूर्णाङ्क) rdclass, (signed पूर्णाङ्क) rdtype,
	    answer, परिमाण(answer));
	यदि (length < 0) {
		विकल्प(h_errno) {
		पक्ष HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			गच्छ fail;
		पक्ष NO_DATA:
			result = ERRSET_NODATA;
			गच्छ fail;
		स्वभाव:
			result = ERRSET_FAIL;
			गच्छ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	यदि (response == रिक्त) {
		result = ERRSET_FAIL;
		गच्छ fail;
	}

	यदि (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		गच्छ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, परिमाण(संरचना rrsetinfo));
	यदि (rrset == रिक्त) {
		result = ERRSET_NOMEMORY;
		गच्छ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	यदि (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	यदि (rrset->rri_name == रिक्त) {
		result = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = मोजणी_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = मोजणी_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    परिमाण(संरचना rdatainfo));
	यदि (rrset->rri_rdatas == रिक्त) {
		result = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	/* allocate memory for signatures */
	यदि (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, परिमाण(संरचना rdatainfo));
		यदि (rrset->rri_sigs == रिक्त) {
			result = ERRSET_NOMEMORY;
			गच्छ fail;
		}
	}

	/* copy answers & signatures */
	प्रति (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = रिक्त;

		यदि (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		यदि (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		यदि (rdata) {
			rdata->rdi_length = rr->size;
			यदि (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				यदि (rdata->rdi_data == रिक्त) {
					result = ERRSET_NOMEMORY;
					गच्छ fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	प्रत्यागम (ERRSET_SUCCESS);

fail:
	यदि (rrset != रिक्त)
		freerrset(rrset);
	यदि (response != रिक्त)
		free_dns_response(response);
	प्रत्यागम (result);
}

शून्य
freerrset(संरचना rrsetinfo *rrset)
{
	u_int16_t i;

	यदि (rrset == रिक्त)
		प्रत्यागम;

	यदि (rrset->rri_rdatas) {
		प्रति (i = 0; i < rrset->rri_nrdatas; i++) {
			यदि (rrset->rri_rdatas[i].rdi_data == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_rdatas[i].rdi_data);
		}
		मुक्त(rrset->rri_rdatas);
	}

	यदि (rrset->rri_sigs) {
		प्रति (i = 0; i < rrset->rri_nsigs; i++) {
			यदि (rrset->rri_sigs[i].rdi_data == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_sigs[i].rdi_data);
		}
		मुक्त(rrset->rri_sigs);
	}

	यदि (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}

/*
 * DNS response parsing routines
 */
स्थिर संरचना dns_response *
parse_dns_response(ध्रुव u_char *answer, पूर्णाङ्क size)
{
	संरचना dns_response *resp;
	ध्रुव u_char *cp;

	यदि (size < HFIXEDSZ)
		प्रत्यागम (रिक्त);

	/* allocate memory for the response */
	resp = calloc(1, परिमाण(*resp));
	यदि (resp == रिक्त)
		प्रत्यागम (रिक्त);

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
	यदि (resp->header.qdcount < 1) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	यदि (resp->header.qdcount && resp->query == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	यदि (resp->header.ancount && resp->answer == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	यदि (resp->header.nscount && resp->authority == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	यदि (resp->header.arcount && resp->additional == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	प्रत्यागम (resp);
}

स्थिर संरचना dns_query *
parse_dns_qsection(ध्रुव u_char *answer, पूर्णाङ्क size, ध्रुव u_char **cp, पूर्णाङ्क मोजणी)
{
	संरचना dns_query *head, *curr, *prev;
	पूर्णाङ्क i, length;
	वर्ण name[MAXDNAME];

#define NEED(need) \
	कुरु { \
		यदि (*cp + need > answer + size) \
			गच्छ fail; \
	} यावत् (0)

	प्रति (i = 1, head = रिक्त, prev = रिक्त; i <= मोजणी; i++, prev = curr) {
		यदि (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			प्रत्यागम (रिक्त);
		}
		/* allocate and initialize struct */
		curr = calloc(1, परिमाण(संरचना dns_query));
		यदि (curr == रिक्त)
			गच्छ fail;
		यदि (head == रिक्त)
			head = curr;
		यदि (prev != रिक्त)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    परिमाण(name));
		यदि (length < 0) {
			free_dns_query(head);
			प्रत्यागम (रिक्त);
		}
		curr->name = strdup(name);
		यदि (curr->name == रिक्त) {
			free_dns_query(head);
			प्रत्यागम (रिक्त);
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

	प्रत्यागम (head);
}

स्थिर संरचना dns_rr *
parse_dns_rrsection(ध्रुव u_char *answer, पूर्णाङ्क size, ध्रुव u_char **cp,
    पूर्णाङ्क मोजणी)
{
	संरचना dns_rr *head, *curr, *prev;
	पूर्णाङ्क i, length;
	वर्ण name[MAXDNAME];

#define NEED(need) \
	कुरु { \
		यदि (*cp + need > answer + size) \
			गच्छ fail; \
	} यावत् (0)

	प्रति (i = 1, head = रिक्त, prev = रिक्त; i <= मोजणी; i++, prev = curr) {
		यदि (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			प्रत्यागम (रिक्त);
		}

		/* allocate and initialize struct */
		curr = calloc(1, परिमाण(संरचना dns_rr));
		यदि (curr == रिक्त)
			गच्छ fail;
		यदि (head == रिक्त)
			head = curr;
		यदि (prev != रिक्त)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    परिमाण(name));
		यदि (length < 0) {
			free_dns_rr(head);
			प्रत्यागम (रिक्त);
		}
		curr->name = strdup(name);
		यदि (curr->name == रिक्त) {
			free_dns_rr(head);
			प्रत्यागम (रिक्त);
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
		यदि (curr->size != 0) {
			यदि ((curr->rdata = malloc(curr->size)) == रिक्त) {
				free_dns_rr(head);
				प्रत्यागम (रिक्त);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	प्रत्यागम (head);
}

स्थिर शून्य
free_dns_query(संरचना dns_query *p)
{
	संरचना dns_query *next;

	यावत् (p != रिक्त) {
		next = p->next;
		मुक्त(p->name);
		मुक्त(p);
		p = next;
	}
}

स्थिर शून्य
free_dns_rr(संरचना dns_rr *p)
{
	संरचना dns_rr *next;

	यावत् (p != रिक्त) {
		next = p->next;
		मुक्त(p->name);
		मुक्त(p->rdata);
		मुक्त(p);
		p = next;
	}
}

स्थिर शून्य
free_dns_response(संरचना dns_response *p)
{
	यदि (p == रिक्त)
		प्रत्यागम;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	मुक्त(p);
}

स्थिर पूर्णाङ्क
मोजणी_dns_rr(संरचना dns_rr *p, u_int16_t class, u_int16_t type)
{
	पूर्णाङ्क n = 0;

	यावत्(p) {
		यदि (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	प्रत्यागम (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
