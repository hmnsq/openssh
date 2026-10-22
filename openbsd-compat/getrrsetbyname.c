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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ "getrrsetbyname.h"

#എങ്കിൽ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
ബാഹ്യ പൂർണ്ണസംഖ്യ h_errno;
#endif

/* We don't need multithread support here */
#ifdef _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#endif
#define _THREAD_PRIVATE(a,b,c) (c)

#ifndef HAVE__RES_EXTERN
ഘടന __res_state _res;
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
#എങ്കിൽ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
സ്ഥിതം u_int16_t
_getshort(സ്ഥിരം u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	തിരികെ (u);
}

സ്ഥിതം u_int32_t
_getlong(സ്ഥിരം u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	തിരികെ (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

ഘടന dns_query {
	അക്ഷരം			*name;
	u_int16_t		type;
	u_int16_t		class;
	ഘടന dns_query	*next;
};

ഘടന dns_rr {
	അക്ഷരം			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		size;
	ശൂന്യം			*rdata;
	ഘടന dns_rr		*next;
};

ഘടന dns_response {
	HEADER			header;
	ഘടന dns_query	*query;
	ഘടന dns_rr		*answer;
	ഘടന dns_rr		*authority;
	ഘടന dns_rr		*additional;
};

സ്ഥിതം ഘടന dns_response *parse_dns_response(സ്ഥിരം u_char *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം ഘടന dns_query *parse_dns_qsection(സ്ഥിരം u_char *, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം u_char **, പൂർണ്ണസംഖ്യ);
സ്ഥിതം ഘടന dns_rr *parse_dns_rrsection(സ്ഥിരം u_char *, പൂർണ്ണസംഖ്യ, സ്ഥിരം u_char **,
    പൂർണ്ണസംഖ്യ);

സ്ഥിതം ശൂന്യം free_dns_query(ഘടന dns_query *);
സ്ഥിതം ശൂന്യം free_dns_rr(ഘടന dns_rr *);
സ്ഥിതം ശൂന്യം free_dns_response(ഘടന dns_response *);

സ്ഥിതം പൂർണ്ണസംഖ്യ എണ്ണം_dns_rr(ഘടന dns_rr *, u_int16_t, u_int16_t);

പൂർണ്ണസംഖ്യ
getrrsetbyname(സ്ഥിരം അക്ഷരം *hostname, unsigned പൂർണ്ണസംഖ്യ rdclass,
    unsigned പൂർണ്ണസംഖ്യ rdtype, unsigned പൂർണ്ണസംഖ്യ flags,
    ഘടന rrsetinfo **res)
{
	ഘടന __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	പൂർണ്ണസംഖ്യ result;
	ഘടന rrsetinfo *rrset = ശൂന്യ;
	ഘടന dns_response *response = ശൂന്യ;
	ഘടന dns_rr *rr;
	ഘടന rdatainfo *rdata;
	പൂർണ്ണസംഖ്യ length;
	unsigned പൂർണ്ണസംഖ്യ index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	എങ്കിൽ (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		പോകുക fail;
	}

	/* don't allow queries of class or type ANY */
	എങ്കിൽ (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		പോകുക fail;
	}

	/* don't allow flags yet, unimplemented */
	എങ്കിൽ (flags) {
		result = ERRSET_INVAL;
		പോകുക fail;
	}

	/* initialize resolver */
	എങ്കിൽ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		പോകുക fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	എങ്കിൽ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (signed പൂർണ്ണസംഖ്യ) rdclass, (signed പൂർണ്ണസംഖ്യ) rdtype,
	    answer, വലുപ്പം(answer));
	എങ്കിൽ (length < 0) {
		തിരഞ്ഞെടുപ്പ്(h_errno) {
		അവസ്ഥ HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			പോകുക fail;
		അവസ്ഥ NO_DATA:
			result = ERRSET_NODATA;
			പോകുക fail;
		സ്ഥിരസ്ഥിതി:
			result = ERRSET_FAIL;
			പോകുക fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	എങ്കിൽ (response == ശൂന്യ) {
		result = ERRSET_FAIL;
		പോകുക fail;
	}

	എങ്കിൽ (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		പോകുക fail;
	}

	/* initialize rrset */
	rrset = calloc(1, വലുപ്പം(ഘടന rrsetinfo));
	എങ്കിൽ (rrset == ശൂന്യ) {
		result = ERRSET_NOMEMORY;
		പോകുക fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	എങ്കിൽ (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	എങ്കിൽ (rrset->rri_name == ശൂന്യ) {
		result = ERRSET_NOMEMORY;
		പോകുക fail;
	}

	/* count answers */
	rrset->rri_nrdatas = എണ്ണം_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = എണ്ണം_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	    വലുപ്പം(ഘടന rdatainfo));
	എങ്കിൽ (rrset->rri_rdatas == ശൂന്യ) {
		result = ERRSET_NOMEMORY;
		പോകുക fail;
	}

	/* allocate memory for signatures */
	എങ്കിൽ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs, വലുപ്പം(ഘടന rdatainfo));
		എങ്കിൽ (rrset->rri_sigs == ശൂന്യ) {
			result = ERRSET_NOMEMORY;
			പോകുക fail;
		}
	}

	/* copy answers & signatures */
	വേണ്ടി (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = ശൂന്യ;

		എങ്കിൽ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		എങ്കിൽ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		എങ്കിൽ (rdata) {
			rdata->rdi_length = rr->size;
			എങ്കിൽ (rr->size != 0) {
				rdata->rdi_data   = malloc(rr->size);
				എങ്കിൽ (rdata->rdi_data == ശൂന്യ) {
					result = ERRSET_NOMEMORY;
					പോകുക fail;
				}
				memcpy(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	തിരികെ (ERRSET_SUCCESS);

fail:
	എങ്കിൽ (rrset != ശൂന്യ)
		freerrset(rrset);
	എങ്കിൽ (response != ശൂന്യ)
		free_dns_response(response);
	തിരികെ (result);
}

ശൂന്യം
freerrset(ഘടന rrsetinfo *rrset)
{
	u_int16_t i;

	എങ്കിൽ (rrset == ശൂന്യ)
		തിരികെ;

	എങ്കിൽ (rrset->rri_rdatas) {
		വേണ്ടി (i = 0; i < rrset->rri_nrdatas; i++) {
			എങ്കിൽ (rrset->rri_rdatas[i].rdi_data == ശൂന്യ)
				നിർത്തുക;
			സ്വതന്ത്രം(rrset->rri_rdatas[i].rdi_data);
		}
		സ്വതന്ത്രം(rrset->rri_rdatas);
	}

	എങ്കിൽ (rrset->rri_sigs) {
		വേണ്ടി (i = 0; i < rrset->rri_nsigs; i++) {
			എങ്കിൽ (rrset->rri_sigs[i].rdi_data == ശൂന്യ)
				നിർത്തുക;
			സ്വതന്ത്രം(rrset->rri_sigs[i].rdi_data);
		}
		സ്വതന്ത്രം(rrset->rri_sigs);
	}

	എങ്കിൽ (rrset->rri_name)
		സ്വതന്ത്രം(rrset->rri_name);
	സ്വതന്ത്രം(rrset);
}

/*
 * DNS response parsing routines
 */
സ്ഥിതം ഘടന dns_response *
parse_dns_response(സ്ഥിരം u_char *answer, പൂർണ്ണസംഖ്യ size)
{
	ഘടന dns_response *resp;
	സ്ഥിരം u_char *cp;

	എങ്കിൽ (size < HFIXEDSZ)
		തിരികെ (ശൂന്യ);

	/* allocate memory for the response */
	resp = calloc(1, വലുപ്പം(*resp));
	എങ്കിൽ (resp == ശൂന്യ)
		തിരികെ (ശൂന്യ);

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
	എങ്കിൽ (resp->header.qdcount < 1) {
		free_dns_response(resp);
		തിരികെ (ശൂന്യ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	എങ്കിൽ (resp->header.qdcount && resp->query == ശൂന്യ) {
		free_dns_response(resp);
		തിരികെ (ശൂന്യ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	എങ്കിൽ (resp->header.ancount && resp->answer == ശൂന്യ) {
		free_dns_response(resp);
		തിരികെ (ശൂന്യ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	എങ്കിൽ (resp->header.nscount && resp->authority == ശൂന്യ) {
		free_dns_response(resp);
		തിരികെ (ശൂന്യ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	എങ്കിൽ (resp->header.arcount && resp->additional == ശൂന്യ) {
		free_dns_response(resp);
		തിരികെ (ശൂന്യ);
	}

	തിരികെ (resp);
}

സ്ഥിതം ഘടന dns_query *
parse_dns_qsection(സ്ഥിരം u_char *answer, പൂർണ്ണസംഖ്യ size, സ്ഥിരം u_char **cp, പൂർണ്ണസംഖ്യ എണ്ണം)
{
	ഘടന dns_query *head, *curr, *prev;
	പൂർണ്ണസംഖ്യ i, length;
	അക്ഷരം name[MAXDNAME];

#define NEED(need) \
	ചെയ്യുക { \
		എങ്കിൽ (*cp + need > answer + size) \
			പോകുക fail; \
	} ആകുമ്പോൾ (0)

	വേണ്ടി (i = 1, head = ശൂന്യ, prev = ശൂന്യ; i <= എണ്ണം; i++, prev = curr) {
		എങ്കിൽ (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			തിരികെ (ശൂന്യ);
		}
		/* allocate and initialize struct */
		curr = calloc(1, വലുപ്പം(ഘടന dns_query));
		എങ്കിൽ (curr == ശൂന്യ)
			പോകുക fail;
		എങ്കിൽ (head == ശൂന്യ)
			head = curr;
		എങ്കിൽ (prev != ശൂന്യ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    വലുപ്പം(name));
		എങ്കിൽ (length < 0) {
			free_dns_query(head);
			തിരികെ (ശൂന്യ);
		}
		curr->name = strdup(name);
		എങ്കിൽ (curr->name == ശൂന്യ) {
			free_dns_query(head);
			തിരികെ (ശൂന്യ);
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

	തിരികെ (head);
}

സ്ഥിതം ഘടന dns_rr *
parse_dns_rrsection(സ്ഥിരം u_char *answer, പൂർണ്ണസംഖ്യ size, സ്ഥിരം u_char **cp,
    പൂർണ്ണസംഖ്യ എണ്ണം)
{
	ഘടന dns_rr *head, *curr, *prev;
	പൂർണ്ണസംഖ്യ i, length;
	അക്ഷരം name[MAXDNAME];

#define NEED(need) \
	ചെയ്യുക { \
		എങ്കിൽ (*cp + need > answer + size) \
			പോകുക fail; \
	} ആകുമ്പോൾ (0)

	വേണ്ടി (i = 1, head = ശൂന്യ, prev = ശൂന്യ; i <= എണ്ണം; i++, prev = curr) {
		എങ്കിൽ (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			തിരികെ (ശൂന്യ);
		}

		/* allocate and initialize struct */
		curr = calloc(1, വലുപ്പം(ഘടന dns_rr));
		എങ്കിൽ (curr == ശൂന്യ)
			പോകുക fail;
		എങ്കിൽ (head == ശൂന്യ)
			head = curr;
		എങ്കിൽ (prev != ശൂന്യ)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    വലുപ്പം(name));
		എങ്കിൽ (length < 0) {
			free_dns_rr(head);
			തിരികെ (ശൂന്യ);
		}
		curr->name = strdup(name);
		എങ്കിൽ (curr->name == ശൂന്യ) {
			free_dns_rr(head);
			തിരികെ (ശൂന്യ);
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
		എങ്കിൽ (curr->size != 0) {
			എങ്കിൽ ((curr->rdata = malloc(curr->size)) == ശൂന്യ) {
				free_dns_rr(head);
				തിരികെ (ശൂന്യ);
			}
			memcpy(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	തിരികെ (head);
}

സ്ഥിതം ശൂന്യം
free_dns_query(ഘടന dns_query *p)
{
	ഘടന dns_query *next;

	ആകുമ്പോൾ (p != ശൂന്യ) {
		next = p->next;
		സ്വതന്ത്രം(p->name);
		സ്വതന്ത്രം(p);
		p = next;
	}
}

സ്ഥിതം ശൂന്യം
free_dns_rr(ഘടന dns_rr *p)
{
	ഘടന dns_rr *next;

	ആകുമ്പോൾ (p != ശൂന്യ) {
		next = p->next;
		സ്വതന്ത്രം(p->name);
		സ്വതന്ത്രം(p->rdata);
		സ്വതന്ത്രം(p);
		p = next;
	}
}

സ്ഥിതം ശൂന്യം
free_dns_response(ഘടന dns_response *p)
{
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	സ്വതന്ത്രം(p);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
എണ്ണം_dns_rr(ഘടന dns_rr *p, u_int16_t class, u_int16_t type)
{
	പൂർണ്ണസംഖ്യ n = 0;

	ആകുമ്പോൾ(p) {
		എങ്കിൽ (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	തിരികെ (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
