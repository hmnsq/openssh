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
#यदि_अन्तः

/* We don't need multithread support here */
#यदि_परिभाषितम् THREAD_वैयक्तिकम्
# undef THREAD_वैयक्तिकम्
#यदि_अन्तः
#परिभाषय THREAD_वैयक्तिकम्(a,b,c) (c)

#यदि_अपरिभाषितम् HAVE__RES_EXTERN
संरचना __res_state _res;
#यदि_अन्तः

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#यदि_अपरिभाषितम् INT32SZ
# define INT32SZ	4
#यदि_अन्तः
#यदि_अपरिभाषितम् INT16SZ
# define INT16SZ	2
#यदि_अन्तः

#यदि_अपरिभाषितम् GETSHORT
#परिभाषय GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#यदि_अन्तः

#यदि_अपरिभाषितम् GETLONG
#परिभाषय GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#यदि_अन्तः

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
#यदि_अन्तः /* missing _getshort/_getlong */

/* ************** */

#परिभाषय ANSWER_बफर_आकार 0xffff

संरचना dns_query {
	वर्ण			*name;
	u_int16_t		type;
	u_int16_t		class;
	संरचना dns_query	*अग्र;
};

संरचना dns_rr {
	वर्ण			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		आकार;
	शून्य			*rdata;
	संरचना dns_rr		*अग्र;
};

संरचना dns_response {
	शीर्षकम्_2			शीर्षकम्_3;
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

स्थिर पूर्णाङ्क गणनम्_dns_rr(संरचना dns_rr *, u_int16_t, u_int16_t);

पूर्णाङ्क
getrrsetbyname(ध्रुव वर्ण *hostname, अचिह्नित पूर्णाङ्क rdclass,
    अचिह्नित पूर्णाङ्क rdtype, अचिह्नित पूर्णाङ्क flags,
    संरचना rrsetinfo **res)
{
	संरचना __res_state *_resp = THREAD_वैयक्तिकम्(_res, _res, &_res);
	पूर्णाङ्क परिणाम;
	संरचना rrsetinfo *rrset = रिक्त;
	संरचना dns_response *response = रिक्त;
	संरचना dns_rr *rr;
	संरचना rdatainfo *rdata;
	पूर्णाङ्क दीर्घता;
	अचिह्नित पूर्णाङ्क सूचकांक_ans, सूचकांक_sig;
	u_char answer[ANSWER_बफर_आकार];

	/* check for invalid class and type */
	यदि (rdclass > 0xffff || rdtype > 0xffff) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow queries of class or type ANY */
	यदि (rdclass == 0xff || rdtype == 0xff) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow flags yet, unimplemented */
	यदि (flags) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* initialize resolver */
	यदि ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		परिणाम = ERRSET_FAIL;
		गच्छ fail;
	}

#यदि_परिभाषितम् DEBUG
	_resp->options |= RES_DEBUG;
#यदि_अन्तः /* DEBUG */

#यदि_परिभाषितम् RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	यदि (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#यदि_अन्तः /* RES_USE_DNSEC */

	/* make query */
	दीर्घता = res_query(hostname, (चिह्नित पूर्णाङ्क) rdclass, (चिह्नित पूर्णाङ्क) rdtype,
	    answer, परिमाण(answer));
	यदि (दीर्घता < 0) {
		विकल्प(h_errno) {
		पक्ष HOST_NOT_FOUND:
			परिणाम = ERRSET_NONAME;
			गच्छ fail;
		पक्ष NO_DATA:
			परिणाम = ERRSET_NODATA;
			गच्छ fail;
		स्वभाव:
			परिणाम = ERRSET_FAIL;
			गच्छ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, दीर्घता);
	यदि (response == रिक्त) {
		परिणाम = ERRSET_FAIL;
		गच्छ fail;
	}

	यदि (response->शीर्षकम्_3.qdcount != 1) {
		परिणाम = ERRSET_FAIL;
		गच्छ fail;
	}

	/* initialize rrset */
	rrset = शून्यस्मृतिं_देहि(1, परिमाण(संरचना rrsetinfo));
	यदि (rrset == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->शीर्षकम्_3.ancount;

#यदि_परिभाषितम् HAVE_शीर्षकम्_AD
	/* check for authenticated data */
	यदि (response->शीर्षकम्_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#यदि_अन्तः

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	यदि (rrset->rri_name == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = गणनम्_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = गणनम्_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = शून्यस्मृतिं_देहि(rrset->rri_nrdatas,
	    परिमाण(संरचना rdatainfo));
	यदि (rrset->rri_rdatas == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	/* allocate memory for signatures */
	यदि (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = शून्यस्मृतिं_देहि(rrset->rri_nsigs, परिमाण(संरचना rdatainfo));
		यदि (rrset->rri_sigs == रिक्त) {
			परिणाम = ERRSET_NOMEMORY;
			गच्छ fail;
		}
	}

	/* copy answers & signatures */
	प्रति (rr = response->answer, सूचकांक_ans = 0, सूचकांक_sig = 0;
	    rr; rr = rr->अग्र) {

		rdata = रिक्त;

		यदि (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[सूचकांक_ans++];

		यदि (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[सूचकांक_sig++];

		यदि (rdata) {
			rdata->rdi_दीर्घता = rr->आकार;
			यदि (rr->आकार != 0) {
				rdata->rdi_दत्त   = स्मृतिं_देहि(rr->आकार);
				यदि (rdata->rdi_दत्त == रिक्त) {
					परिणाम = ERRSET_NOMEMORY;
					गच्छ fail;
				}
				स्मृतिं_प्रतिलिख(rdata->rdi_दत्त, rr->rdata, rr->आकार);
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
	प्रत्यागम (परिणाम);
}

शून्य
freerrset(संरचना rrsetinfo *rrset)
{
	u_int16_t i;

	यदि (rrset == रिक्त)
		प्रत्यागम;

	यदि (rrset->rri_rdatas) {
		प्रति (i = 0; i < rrset->rri_nrdatas; i++) {
			यदि (rrset->rri_rdatas[i].rdi_दत्त == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_rdatas[i].rdi_दत्त);
		}
		मुक्त(rrset->rri_rdatas);
	}

	यदि (rrset->rri_sigs) {
		प्रति (i = 0; i < rrset->rri_nsigs; i++) {
			यदि (rrset->rri_sigs[i].rdi_दत्त == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_sigs[i].rdi_दत्त);
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
parse_dns_response(ध्रुव u_char *answer, पूर्णाङ्क आकार)
{
	संरचना dns_response *resp;
	ध्रुव u_char *cp;

	यदि (आकार < HFIXEDSZ)
		प्रत्यागम (रिक्त);

	/* allocate memory for the response */
	resp = शून्यस्मृतिं_देहि(1, परिमाण(*resp));
	यदि (resp == रिक्त)
		प्रत्यागम (रिक्त);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	स्मृतिं_प्रतिलिख(&resp->शीर्षकम्_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->शीर्षकम्_3.qdcount = ntohs(resp->शीर्षकम्_3.qdcount);
	resp->शीर्षकम्_3.ancount = ntohs(resp->शीर्षकम्_3.ancount);
	resp->शीर्षकम्_3.nscount = ntohs(resp->शीर्षकम्_3.nscount);
	resp->शीर्षकम्_3.arcount = ntohs(resp->शीर्षकम्_3.arcount);

	/* there must be at least one query */
	यदि (resp->शीर्षकम्_3.qdcount < 1) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, आकार, &cp,
	    resp->शीर्षकम्_3.qdcount);
	यदि (resp->शीर्षकम्_3.qdcount && resp->query == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, आकार, &cp,
	    resp->शीर्षकम्_3.ancount);
	यदि (resp->शीर्षकम्_3.ancount && resp->answer == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, आकार, &cp,
	    resp->शीर्षकम्_3.nscount);
	यदि (resp->शीर्षकम्_3.nscount && resp->authority == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, आकार, &cp,
	    resp->शीर्षकम्_3.arcount);
	यदि (resp->शीर्षकम्_3.arcount && resp->additional == रिक्त) {
		free_dns_response(resp);
		प्रत्यागम (रिक्त);
	}

	प्रत्यागम (resp);
}

स्थिर संरचना dns_query *
parse_dns_qsection(ध्रुव u_char *answer, पूर्णाङ्क आकार, ध्रुव u_char **cp, पूर्णाङ्क गणनम्)
{
	संरचना dns_query *शीर्ष, *curr, *पूर्व;
	पूर्णाङ्क i, दीर्घता;
	वर्ण name[MAXDNAME];

#परिभाषय NEED(need) \
	कुरु { \
		यदि (*cp + need > answer + आकार) \
			गच्छ fail; \
	} यावत् (0)

	प्रति (i = 1, शीर्ष = रिक्त, पूर्व = रिक्त; i <= गणनम्; i++, पूर्व = curr) {
		यदि (*cp >= answer + आकार) {
 fail:
			free_dns_query(शीर्ष);
			प्रत्यागम (रिक्त);
		}
		/* allocate and initialize struct */
		curr = शून्यस्मृतिं_देहि(1, परिमाण(संरचना dns_query));
		यदि (curr == रिक्त)
			गच्छ fail;
		यदि (शीर्ष == रिक्त)
			शीर्ष = curr;
		यदि (पूर्व != रिक्त)
			पूर्व->अग्र = curr;

		/* name */
		दीर्घता = dn_expand(answer, answer + आकार, *cp, name,
		    परिमाण(name));
		यदि (दीर्घता < 0) {
			free_dns_query(शीर्ष);
			प्रत्यागम (रिक्त);
		}
		curr->name = strdup(name);
		यदि (curr->name == रिक्त) {
			free_dns_query(शीर्ष);
			प्रत्यागम (रिक्त);
		}
		NEED(दीर्घता);
		*cp += दीर्घता;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#अपरिभाषय NEED

	प्रत्यागम (शीर्ष);
}

स्थिर संरचना dns_rr *
parse_dns_rrsection(ध्रुव u_char *answer, पूर्णाङ्क आकार, ध्रुव u_char **cp,
    पूर्णाङ्क गणनम्)
{
	संरचना dns_rr *शीर्ष, *curr, *पूर्व;
	पूर्णाङ्क i, दीर्घता;
	वर्ण name[MAXDNAME];

#परिभाषय NEED(need) \
	कुरु { \
		यदि (*cp + need > answer + आकार) \
			गच्छ fail; \
	} यावत् (0)

	प्रति (i = 1, शीर्ष = रिक्त, पूर्व = रिक्त; i <= गणनम्; i++, पूर्व = curr) {
		यदि (*cp >= answer + आकार) {
 fail:
			free_dns_rr(शीर्ष);
			प्रत्यागम (रिक्त);
		}

		/* allocate and initialize struct */
		curr = शून्यस्मृतिं_देहि(1, परिमाण(संरचना dns_rr));
		यदि (curr == रिक्त)
			गच्छ fail;
		यदि (शीर्ष == रिक्त)
			शीर्ष = curr;
		यदि (पूर्व != रिक्त)
			पूर्व->अग्र = curr;

		/* name */
		दीर्घता = dn_expand(answer, answer + आकार, *cp, name,
		    परिमाण(name));
		यदि (दीर्घता < 0) {
			free_dns_rr(शीर्ष);
			प्रत्यागम (रिक्त);
		}
		curr->name = strdup(name);
		यदि (curr->name == रिक्त) {
			free_dns_rr(शीर्ष);
			प्रत्यागम (रिक्त);
		}
		NEED(दीर्घता);
		*cp += दीर्घता;

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
		यदि (curr->आकार != 0) {
			यदि ((curr->rdata = स्मृतिं_देहि(curr->आकार)) == रिक्त) {
				free_dns_rr(शीर्ष);
				प्रत्यागम (रिक्त);
			}
			स्मृतिं_प्रतिलिख(curr->rdata, *cp, curr->आकार);
		}
		*cp += curr->आकार;
	}
#अपरिभाषय NEED

	प्रत्यागम (शीर्ष);
}

स्थिर शून्य
free_dns_query(संरचना dns_query *p)
{
	संरचना dns_query *अग्र;

	यावत् (p != रिक्त) {
		अग्र = p->अग्र;
		मुक्त(p->name);
		मुक्त(p);
		p = अग्र;
	}
}

स्थिर शून्य
free_dns_rr(संरचना dns_rr *p)
{
	संरचना dns_rr *अग्र;

	यावत् (p != रिक्त) {
		अग्र = p->अग्र;
		मुक्त(p->name);
		मुक्त(p->rdata);
		मुक्त(p);
		p = अग्र;
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
गणनम्_dns_rr(संरचना dns_rr *p, u_int16_t class, u_int16_t type)
{
	पूर्णाङ्क n = 0;

	यावत्(p) {
		यदि (p->class == class && p->type == type)
			n++;
		p = p->अग्र;
	}

	प्रत्यागम (n);
}

#यदि_अन्तः /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
