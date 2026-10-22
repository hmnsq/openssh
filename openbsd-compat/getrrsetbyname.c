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

#जर !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव "getrrsetbyname.h"

#जर defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
बाह्य पूर्णांक h_errno;
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
#जर !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
_getshort(स्थिरांक u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	परत (u);
}

स्थिर u_int32_t
_getlong(स्थिरांक u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	परत (u);
}
#endif /* missing _getshort/_getlong */

/* ************** */

#define ANSWER_BUFFER_SIZE 0xffff

संरचना dns_query {
	अक्षर			*name;
	u_int16_t		type;
	u_int16_t		class;
	संरचना dns_query	*next;
};

संरचना dns_rr {
	अक्षर			*name;
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

स्थिर संरचना dns_response *parse_dns_response(स्थिरांक u_char *, पूर्णांक);
स्थिर संरचना dns_query *parse_dns_qsection(स्थिरांक u_char *, पूर्णांक,
    स्थिरांक u_char **, पूर्णांक);
स्थिर संरचना dns_rr *parse_dns_rrsection(स्थिरांक u_char *, पूर्णांक, स्थिरांक u_char **,
    पूर्णांक);

स्थिर शून्य free_dns_query(संरचना dns_query *);
स्थिर शून्य free_dns_rr(संरचना dns_rr *);
स्थिर शून्य free_dns_response(संरचना dns_response *);

स्थिर पूर्णांक मोजणी_dns_rr(संरचना dns_rr *, u_int16_t, u_int16_t);

पूर्णांक
getrrsetbyname(स्थिरांक अक्षर *hostname, अचिन्हित पूर्णांक rdclass,
    अचिन्हित पूर्णांक rdtype, अचिन्हित पूर्णांक flags,
    संरचना rrsetinfo **res)
{
	संरचना __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	पूर्णांक result;
	संरचना rrsetinfo *rrset = रिक्त;
	संरचना dns_response *response = रिक्त;
	संरचना dns_rr *rr;
	संरचना rdatainfo *rdata;
	पूर्णांक length;
	अचिन्हित पूर्णांक index_ans, index_sig;
	u_char answer[ANSWER_BUFFER_SIZE];

	/* check for invalid class and type */
	जर (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* don't allow queries of class or type ANY */
	जर (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* don't allow flags yet, unimplemented */
	जर (flags) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* initialize resolver */
	जर ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		result = ERRSET_FAIL;
		जा fail;
	}

#ifdef DEBUG
	_resp->options |= RES_DEBUG;
#endif /* DEBUG */

#ifdef RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	जर (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#endif /* RES_USE_DNSEC */

	/* make query */
	length = res_query(hostname, (चिन्हित पूर्णांक) rdclass, (चिन्हित पूर्णांक) rdtype,
	    answer, आकार(answer));
	जर (length < 0) {
		निवड(h_errno) {
		स्थिती HOST_NOT_FOUND:
			result = ERRSET_NONAME;
			जा fail;
		स्थिती NO_DATA:
			result = ERRSET_NODATA;
			जा fail;
		पूर्वनिर्धारित:
			result = ERRSET_FAIL;
			जा fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, length);
	जर (response == रिक्त) {
		result = ERRSET_FAIL;
		जा fail;
	}

	जर (response->header.qdcount != 1) {
		result = ERRSET_FAIL;
		जा fail;
	}

	/* initialize rrset */
	rrset = सुस्मृति(1, आकार(संरचना rrsetinfo));
	जर (rrset == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#ifdef HAVE_HEADER_AD
	/* check for authenticated data */
	जर (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#endif

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	जर (rrset->rri_name == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}

	/* count answers */
	rrset->rri_nrdatas = मोजणी_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = मोजणी_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = सुस्मृति(rrset->rri_nrdatas,
	    आकार(संरचना rdatainfo));
	जर (rrset->rri_rdatas == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}

	/* allocate memory for signatures */
	जर (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = सुस्मृति(rrset->rri_nsigs, आकार(संरचना rdatainfo));
		जर (rrset->rri_sigs == रिक्त) {
			result = ERRSET_NOMEMORY;
			जा fail;
		}
	}

	/* copy answers & signatures */
	साठी (rr = response->answer, index_ans = 0, index_sig = 0;
	    rr; rr = rr->next) {

		rdata = रिक्त;

		जर (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[index_ans++];

		जर (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[index_sig++];

		जर (rdata) {
			rdata->rdi_length = rr->size;
			जर (rr->size != 0) {
				rdata->rdi_data   = दो_स्मृति(rr->size);
				जर (rdata->rdi_data == रिक्त) {
					result = ERRSET_NOMEMORY;
					जा fail;
				}
				स_नकल(rdata->rdi_data, rr->rdata, rr->size);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	परत (ERRSET_SUCCESS);

fail:
	जर (rrset != रिक्त)
		freerrset(rrset);
	जर (response != रिक्त)
		free_dns_response(response);
	परत (result);
}

शून्य
freerrset(संरचना rrsetinfo *rrset)
{
	u_int16_t i;

	जर (rrset == रिक्त)
		परत;

	जर (rrset->rri_rdatas) {
		साठी (i = 0; i < rrset->rri_nrdatas; i++) {
			जर (rrset->rri_rdatas[i].rdi_data == रिक्त)
				थांबा;
			मुक्त(rrset->rri_rdatas[i].rdi_data);
		}
		मुक्त(rrset->rri_rdatas);
	}

	जर (rrset->rri_sigs) {
		साठी (i = 0; i < rrset->rri_nsigs; i++) {
			जर (rrset->rri_sigs[i].rdi_data == रिक्त)
				थांबा;
			मुक्त(rrset->rri_sigs[i].rdi_data);
		}
		मुक्त(rrset->rri_sigs);
	}

	जर (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}

/*
 * DNS response parsing routines
 */
स्थिर संरचना dns_response *
parse_dns_response(स्थिरांक u_char *answer, पूर्णांक size)
{
	संरचना dns_response *resp;
	स्थिरांक u_char *cp;

	जर (size < HFIXEDSZ)
		परत (रिक्त);

	/* allocate memory for the response */
	resp = सुस्मृति(1, आकार(*resp));
	जर (resp == रिक्त)
		परत (रिक्त);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	स_नकल(&resp->header, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->header.qdcount = ntohs(resp->header.qdcount);
	resp->header.ancount = ntohs(resp->header.ancount);
	resp->header.nscount = ntohs(resp->header.nscount);
	resp->header.arcount = ntohs(resp->header.arcount);

	/* there must be at least one query */
	जर (resp->header.qdcount < 1) {
		free_dns_response(resp);
		परत (रिक्त);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, size, &cp,
	    resp->header.qdcount);
	जर (resp->header.qdcount && resp->query == रिक्त) {
		free_dns_response(resp);
		परत (रिक्त);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, size, &cp,
	    resp->header.ancount);
	जर (resp->header.ancount && resp->answer == रिक्त) {
		free_dns_response(resp);
		परत (रिक्त);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, size, &cp,
	    resp->header.nscount);
	जर (resp->header.nscount && resp->authority == रिक्त) {
		free_dns_response(resp);
		परत (रिक्त);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, size, &cp,
	    resp->header.arcount);
	जर (resp->header.arcount && resp->additional == रिक्त) {
		free_dns_response(resp);
		परत (रिक्त);
	}

	परत (resp);
}

स्थिर संरचना dns_query *
parse_dns_qsection(स्थिरांक u_char *answer, पूर्णांक size, स्थिरांक u_char **cp, पूर्णांक मोजणी)
{
	संरचना dns_query *head, *curr, *prev;
	पूर्णांक i, length;
	अक्षर name[MAXDNAME];

#define NEED(need) \
	करा { \
		जर (*cp + need > answer + size) \
			जा fail; \
	} पर्यंत (0)

	साठी (i = 1, head = रिक्त, prev = रिक्त; i <= मोजणी; i++, prev = curr) {
		जर (*cp >= answer + size) {
 fail:
			free_dns_query(head);
			परत (रिक्त);
		}
		/* allocate and initialize struct */
		curr = सुस्मृति(1, आकार(संरचना dns_query));
		जर (curr == रिक्त)
			जा fail;
		जर (head == रिक्त)
			head = curr;
		जर (prev != रिक्त)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    आकार(name));
		जर (length < 0) {
			free_dns_query(head);
			परत (रिक्त);
		}
		curr->name = strdup(name);
		जर (curr->name == रिक्त) {
			free_dns_query(head);
			परत (रिक्त);
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

	परत (head);
}

स्थिर संरचना dns_rr *
parse_dns_rrsection(स्थिरांक u_char *answer, पूर्णांक size, स्थिरांक u_char **cp,
    पूर्णांक मोजणी)
{
	संरचना dns_rr *head, *curr, *prev;
	पूर्णांक i, length;
	अक्षर name[MAXDNAME];

#define NEED(need) \
	करा { \
		जर (*cp + need > answer + size) \
			जा fail; \
	} पर्यंत (0)

	साठी (i = 1, head = रिक्त, prev = रिक्त; i <= मोजणी; i++, prev = curr) {
		जर (*cp >= answer + size) {
 fail:
			free_dns_rr(head);
			परत (रिक्त);
		}

		/* allocate and initialize struct */
		curr = सुस्मृति(1, आकार(संरचना dns_rr));
		जर (curr == रिक्त)
			जा fail;
		जर (head == रिक्त)
			head = curr;
		जर (prev != रिक्त)
			prev->next = curr;

		/* name */
		length = dn_expand(answer, answer + size, *cp, name,
		    आकार(name));
		जर (length < 0) {
			free_dns_rr(head);
			परत (रिक्त);
		}
		curr->name = strdup(name);
		जर (curr->name == रिक्त) {
			free_dns_rr(head);
			परत (रिक्त);
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
		जर (curr->size != 0) {
			जर ((curr->rdata = दो_स्मृति(curr->size)) == रिक्त) {
				free_dns_rr(head);
				परत (रिक्त);
			}
			स_नकल(curr->rdata, *cp, curr->size);
		}
		*cp += curr->size;
	}
#undef NEED

	परत (head);
}

स्थिर शून्य
free_dns_query(संरचना dns_query *p)
{
	संरचना dns_query *next;

	पर्यंत (p != रिक्त) {
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

	पर्यंत (p != रिक्त) {
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
	जर (p == रिक्त)
		परत;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	मुक्त(p);
}

स्थिर पूर्णांक
मोजणी_dns_rr(संरचना dns_rr *p, u_int16_t class, u_int16_t type)
{
	पूर्णांक n = 0;

	पर्यंत(p) {
		जर (p->class == class && p->type == type)
			n++;
		p = p->next;
	}

	परत (n);
}

#endif /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
