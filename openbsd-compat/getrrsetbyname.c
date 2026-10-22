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

#समावेश "includes.h"

#अगर !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश "getrrsetbyname.h"

#अगर defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
बाह्य पूर्णांक h_errno;
#पूर्ण_अगर

/* We don't need multithread support here */
#अगर_घोषित _THREAD_PRIVATE
# undef _THREAD_PRIVATE
#पूर्ण_अगर
#घोषणा _THREAD_PRIVATE(a,b,c) (c)

#अगर_अघोषित HAVE__RES_EXTERN
काष्ठा __res_state _res;
#पूर्ण_अगर

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#अगर_अघोषित INT32SZ
# define INT32SZ	4
#पूर्ण_अगर
#अगर_अघोषित INT16SZ
# define INT16SZ	2
#पूर्ण_अगर

#अगर_अघोषित GETSHORT
#घोषणा GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#पूर्ण_अगर

#अगर_अघोषित GETLONG
#घोषणा GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#पूर्ण_अगर

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#अगर !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
अटल u_int16_t
_getshort(स्थिर u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	वापस (u);
}

अटल u_int32_t
_getlong(स्थिर u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	वापस (u);
}
#पूर्ण_अगर /* missing _getshort/_getlong */

/* ************** */

#घोषणा ANSWER_बफर_आकार 0xffff

काष्ठा dns_query {
	अक्षर			*name;
	u_int16_t		type;
	u_int16_t		class;
	काष्ठा dns_query	*अग्र;
};

काष्ठा dns_rr {
	अक्षर			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		आकार;
	व्योम			*rdata;
	काष्ठा dns_rr		*अग्र;
};

काष्ठा dns_response {
	HEADER			header;
	काष्ठा dns_query	*query;
	काष्ठा dns_rr		*answer;
	काष्ठा dns_rr		*authority;
	काष्ठा dns_rr		*additional;
};

अटल काष्ठा dns_response *parse_dns_response(स्थिर u_char *, पूर्णांक);
अटल काष्ठा dns_query *parse_dns_qsection(स्थिर u_char *, पूर्णांक,
    स्थिर u_char **, पूर्णांक);
अटल काष्ठा dns_rr *parse_dns_rrsection(स्थिर u_char *, पूर्णांक, स्थिर u_char **,
    पूर्णांक);

अटल व्योम free_dns_query(काष्ठा dns_query *);
अटल व्योम free_dns_rr(काष्ठा dns_rr *);
अटल व्योम free_dns_response(काष्ठा dns_response *);

अटल पूर्णांक गिनती_dns_rr(काष्ठा dns_rr *, u_int16_t, u_int16_t);

पूर्णांक
getrrsetbyname(स्थिर अक्षर *hostname, अचिन्हित पूर्णांक rdclass,
    अचिन्हित पूर्णांक rdtype, अचिन्हित पूर्णांक flags,
    काष्ठा rrsetinfo **res)
{
	काष्ठा __res_state *_resp = _THREAD_PRIVATE(_res, _res, &_res);
	पूर्णांक परिणाम;
	काष्ठा rrsetinfo *rrset = शून्य;
	काष्ठा dns_response *response = शून्य;
	काष्ठा dns_rr *rr;
	काष्ठा rdatainfo *rdata;
	पूर्णांक लंबाई;
	अचिन्हित पूर्णांक सूचकांक_ans, सूचकांक_sig;
	u_char answer[ANSWER_बफर_आकार];

	/* check for invalid class and type */
	अगर (rdclass > 0xffff || rdtype > 0xffff) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* don't allow queries of class or type ANY */
	अगर (rdclass == 0xff || rdtype == 0xff) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* don't allow flags yet, unimplemented */
	अगर (flags) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* initialize resolver */
	अगर ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		परिणाम = ERRSET_FAIL;
		जाओ fail;
	}

#अगर_घोषित DEBUG
	_resp->options |= RES_DEBUG;
#पूर्ण_अगर /* DEBUG */

#अगर_घोषित RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	अगर (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#पूर्ण_अगर /* RES_USE_DNSEC */

	/* make query */
	लंबाई = res_query(hostname, (चिन्हित पूर्णांक) rdclass, (चिन्हित पूर्णांक) rdtype,
	    answer, माप(answer));
	अगर (लंबाई < 0) {
		चयन(h_errno) {
		हाल HOST_NOT_FOUND:
			परिणाम = ERRSET_NONAME;
			जाओ fail;
		हाल NO_DATA:
			परिणाम = ERRSET_NODATA;
			जाओ fail;
		शेष:
			परिणाम = ERRSET_FAIL;
			जाओ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, लंबाई);
	अगर (response == शून्य) {
		परिणाम = ERRSET_FAIL;
		जाओ fail;
	}

	अगर (response->header.qdcount != 1) {
		परिणाम = ERRSET_FAIL;
		जाओ fail;
	}

	/* initialize rrset */
	rrset = सुस्मृति(1, माप(काष्ठा rrsetinfo));
	अगर (rrset == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->header.ancount;

#अगर_घोषित HAVE_HEADER_AD
	/* check for authenticated data */
	अगर (response->header.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#पूर्ण_अगर

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	अगर (rrset->rri_name == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = गिनती_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = गिनती_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = सुस्मृति(rrset->rri_nrdatas,
	    माप(काष्ठा rdatainfo));
	अगर (rrset->rri_rdatas == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}

	/* allocate memory for signatures */
	अगर (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = सुस्मृति(rrset->rri_nsigs, माप(काष्ठा rdatainfo));
		अगर (rrset->rri_sigs == शून्य) {
			परिणाम = ERRSET_NOMEMORY;
			जाओ fail;
		}
	}

	/* copy answers & signatures */
	क्रम (rr = response->answer, सूचकांक_ans = 0, सूचकांक_sig = 0;
	    rr; rr = rr->अग्र) {

		rdata = शून्य;

		अगर (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[सूचकांक_ans++];

		अगर (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[सूचकांक_sig++];

		अगर (rdata) {
			rdata->rdi_लंबाई = rr->आकार;
			अगर (rr->आकार != 0) {
				rdata->rdi_तथ्य   = दो_स्मृति(rr->आकार);
				अगर (rdata->rdi_तथ्य == शून्य) {
					परिणाम = ERRSET_NOMEMORY;
					जाओ fail;
				}
				स_नकल(rdata->rdi_तथ्य, rr->rdata, rr->आकार);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	वापस (ERRSET_SUCCESS);

fail:
	अगर (rrset != शून्य)
		freerrset(rrset);
	अगर (response != शून्य)
		free_dns_response(response);
	वापस (परिणाम);
}

व्योम
freerrset(काष्ठा rrsetinfo *rrset)
{
	u_int16_t i;

	अगर (rrset == शून्य)
		वापस;

	अगर (rrset->rri_rdatas) {
		क्रम (i = 0; i < rrset->rri_nrdatas; i++) {
			अगर (rrset->rri_rdatas[i].rdi_तथ्य == शून्य)
				अवरोध;
			मुक्त(rrset->rri_rdatas[i].rdi_तथ्य);
		}
		मुक्त(rrset->rri_rdatas);
	}

	अगर (rrset->rri_sigs) {
		क्रम (i = 0; i < rrset->rri_nsigs; i++) {
			अगर (rrset->rri_sigs[i].rdi_तथ्य == शून्य)
				अवरोध;
			मुक्त(rrset->rri_sigs[i].rdi_तथ्य);
		}
		मुक्त(rrset->rri_sigs);
	}

	अगर (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}

/*
 * DNS response parsing routines
 */
अटल काष्ठा dns_response *
parse_dns_response(स्थिर u_char *answer, पूर्णांक आकार)
{
	काष्ठा dns_response *resp;
	स्थिर u_char *cp;

	अगर (आकार < HFIXEDSZ)
		वापस (शून्य);

	/* allocate memory for the response */
	resp = सुस्मृति(1, माप(*resp));
	अगर (resp == शून्य)
		वापस (शून्य);

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
	अगर (resp->header.qdcount < 1) {
		free_dns_response(resp);
		वापस (शून्य);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, आकार, &cp,
	    resp->header.qdcount);
	अगर (resp->header.qdcount && resp->query == शून्य) {
		free_dns_response(resp);
		वापस (शून्य);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, आकार, &cp,
	    resp->header.ancount);
	अगर (resp->header.ancount && resp->answer == शून्य) {
		free_dns_response(resp);
		वापस (शून्य);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, आकार, &cp,
	    resp->header.nscount);
	अगर (resp->header.nscount && resp->authority == शून्य) {
		free_dns_response(resp);
		वापस (शून्य);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, आकार, &cp,
	    resp->header.arcount);
	अगर (resp->header.arcount && resp->additional == शून्य) {
		free_dns_response(resp);
		वापस (शून्य);
	}

	वापस (resp);
}

अटल काष्ठा dns_query *
parse_dns_qsection(स्थिर u_char *answer, पूर्णांक आकार, स्थिर u_char **cp, पूर्णांक गिनती)
{
	काष्ठा dns_query *शीर्ष_2, *curr, *पूर्व;
	पूर्णांक i, लंबाई;
	अक्षर name[MAXDNAME];

#घोषणा NEED(need) \
	करो { \
		अगर (*cp + need > answer + आकार) \
			जाओ fail; \
	} जबतक (0)

	क्रम (i = 1, शीर्ष_2 = शून्य, पूर्व = शून्य; i <= गिनती; i++, पूर्व = curr) {
		अगर (*cp >= answer + आकार) {
 fail:
			free_dns_query(शीर्ष_2);
			वापस (शून्य);
		}
		/* allocate and initialize struct */
		curr = सुस्मृति(1, माप(काष्ठा dns_query));
		अगर (curr == शून्य)
			जाओ fail;
		अगर (शीर्ष_2 == शून्य)
			शीर्ष_2 = curr;
		अगर (पूर्व != शून्य)
			पूर्व->अग्र = curr;

		/* name */
		लंबाई = dn_expand(answer, answer + आकार, *cp, name,
		    माप(name));
		अगर (लंबाई < 0) {
			free_dns_query(शीर्ष_2);
			वापस (शून्य);
		}
		curr->name = strdup(name);
		अगर (curr->name == शून्य) {
			free_dns_query(शीर्ष_2);
			वापस (शून्य);
		}
		NEED(लंबाई);
		*cp += लंबाई;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#अघोषित NEED

	वापस (शीर्ष_2);
}

अटल काष्ठा dns_rr *
parse_dns_rrsection(स्थिर u_char *answer, पूर्णांक आकार, स्थिर u_char **cp,
    पूर्णांक गिनती)
{
	काष्ठा dns_rr *शीर्ष_2, *curr, *पूर्व;
	पूर्णांक i, लंबाई;
	अक्षर name[MAXDNAME];

#घोषणा NEED(need) \
	करो { \
		अगर (*cp + need > answer + आकार) \
			जाओ fail; \
	} जबतक (0)

	क्रम (i = 1, शीर्ष_2 = शून्य, पूर्व = शून्य; i <= गिनती; i++, पूर्व = curr) {
		अगर (*cp >= answer + आकार) {
 fail:
			free_dns_rr(शीर्ष_2);
			वापस (शून्य);
		}

		/* allocate and initialize struct */
		curr = सुस्मृति(1, माप(काष्ठा dns_rr));
		अगर (curr == शून्य)
			जाओ fail;
		अगर (शीर्ष_2 == शून्य)
			शीर्ष_2 = curr;
		अगर (पूर्व != शून्य)
			पूर्व->अग्र = curr;

		/* name */
		लंबाई = dn_expand(answer, answer + आकार, *cp, name,
		    माप(name));
		अगर (लंबाई < 0) {
			free_dns_rr(शीर्ष_2);
			वापस (शून्य);
		}
		curr->name = strdup(name);
		अगर (curr->name == शून्य) {
			free_dns_rr(शीर्ष_2);
			वापस (शून्य);
		}
		NEED(लंबाई);
		*cp += लंबाई;

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
		curr->आकार = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->आकार);
		अगर (curr->आकार != 0) {
			अगर ((curr->rdata = दो_स्मृति(curr->आकार)) == शून्य) {
				free_dns_rr(शीर्ष_2);
				वापस (शून्य);
			}
			स_नकल(curr->rdata, *cp, curr->आकार);
		}
		*cp += curr->आकार;
	}
#अघोषित NEED

	वापस (शीर्ष_2);
}

अटल व्योम
free_dns_query(काष्ठा dns_query *p)
{
	काष्ठा dns_query *अग्र;

	जबतक (p != शून्य) {
		अग्र = p->अग्र;
		मुक्त(p->name);
		मुक्त(p);
		p = अग्र;
	}
}

अटल व्योम
free_dns_rr(काष्ठा dns_rr *p)
{
	काष्ठा dns_rr *अग्र;

	जबतक (p != शून्य) {
		अग्र = p->अग्र;
		मुक्त(p->name);
		मुक्त(p->rdata);
		मुक्त(p);
		p = अग्र;
	}
}

अटल व्योम
free_dns_response(काष्ठा dns_response *p)
{
	अगर (p == शून्य)
		वापस;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	मुक्त(p);
}

अटल पूर्णांक
गिनती_dns_rr(काष्ठा dns_rr *p, u_int16_t class, u_int16_t type)
{
	पूर्णांक n = 0;

	जबतक(p) {
		अगर (p->class == class && p->type == type)
			n++;
		p = p->अग्र;
	}

	वापस (n);
}

#पूर्ण_अगर /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
