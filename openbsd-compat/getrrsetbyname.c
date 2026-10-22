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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ "getrrsetbyname.h"

#ఒకవేళ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
బాహ్య పూర్ణాంకం h_errno;
#అయితే_ముగింపు

/* We don't need multithread support here */
#నిర్వచితమైతే THREAD_వ్యక్తిగత
# undef THREAD_వ్యక్తిగత
#అయితే_ముగింపు
#నిర్వచించు THREAD_వ్యక్తిగత(a,b,c) (c)

#నిర్వచితం_కాకపోతే HAVE__RES_EXTERN
నిర్మాణం __res_state _res;
#అయితే_ముగింపు

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#నిర్వచితం_కాకపోతే INT32SZ
# define INT32SZ	4
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే INT16SZ
# define INT16SZ	2
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే GETSHORT
#నిర్వచించు GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే GETLONG
#నిర్వచించు GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#అయితే_ముగింపు

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#ఒకవేళ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
స్థిర u_int16_t
_getshort(స్థిరరాశి u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	తిరిగి (u);
}

స్థిర u_int32_t
_getlong(స్థిరరాశి u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	తిరిగి (u);
}
#అయితే_ముగింపు /* missing _getshort/_getlong */

/* ************** */

#నిర్వచించు ANSWER_బఫరు_కొలత 0xffff

నిర్మాణం dns_query {
	అక్షరం			*name;
	u_int16_t		type;
	u_int16_t		class;
	నిర్మాణం dns_query	*తదుపరి;
};

నిర్మాణం dns_rr {
	అక్షరం			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		కొలత;
	శూన్య			*rdata;
	నిర్మాణం dns_rr		*తదుపరి;
};

నిర్మాణం dns_response {
	శీర్షిక_2			శీర్షిక_3;
	నిర్మాణం dns_query	*query;
	నిర్మాణం dns_rr		*answer;
	నిర్మాణం dns_rr		*authority;
	నిర్మాణం dns_rr		*additional;
};

స్థిర నిర్మాణం dns_response *parse_dns_response(స్థిరరాశి u_char *, పూర్ణాంకం);
స్థిర నిర్మాణం dns_query *parse_dns_qsection(స్థిరరాశి u_char *, పూర్ణాంకం,
    స్థిరరాశి u_char **, పూర్ణాంకం);
స్థిర నిర్మాణం dns_rr *parse_dns_rrsection(స్థిరరాశి u_char *, పూర్ణాంకం, స్థిరరాశి u_char **,
    పూర్ణాంకం);

స్థిర శూన్య free_dns_query(నిర్మాణం dns_query *);
స్థిర శూన్య free_dns_rr(నిర్మాణం dns_rr *);
స్థిర శూన్య free_dns_response(నిర్మాణం dns_response *);

స్థిర పూర్ణాంకం లెక్క_dns_rr(నిర్మాణం dns_rr *, u_int16_t, u_int16_t);

పూర్ణాంకం
getrrsetbyname(స్థిరరాశి అక్షరం *hostname, గుర్తులేని పూర్ణాంకం rdclass,
    గుర్తులేని పూర్ణాంకం rdtype, గుర్తులేని పూర్ణాంకం flags,
    నిర్మాణం rrsetinfo **res)
{
	నిర్మాణం __res_state *_resp = THREAD_వ్యక్తిగత(_res, _res, &_res);
	పూర్ణాంకం ఫలితం;
	నిర్మాణం rrsetinfo *rrset = ఖాళీ;
	నిర్మాణం dns_response *response = ఖాళీ;
	నిర్మాణం dns_rr *rr;
	నిర్మాణం rdatainfo *rdata;
	పూర్ణాంకం నిడివి;
	గుర్తులేని పూర్ణాంకం సూచీ_ans, సూచీ_sig;
	u_char answer[ANSWER_బఫరు_కొలత];

	/* check for invalid class and type */
	ఒకవేళ (rdclass > 0xffff || rdtype > 0xffff) {
		ఫలితం = ERRSET_INVAL;
		వెళ్ళు fail;
	}

	/* don't allow queries of class or type ANY */
	ఒకవేళ (rdclass == 0xff || rdtype == 0xff) {
		ఫలితం = ERRSET_INVAL;
		వెళ్ళు fail;
	}

	/* don't allow flags yet, unimplemented */
	ఒకవేళ (flags) {
		ఫలితం = ERRSET_INVAL;
		వెళ్ళు fail;
	}

	/* initialize resolver */
	ఒకవేళ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		ఫలితం = ERRSET_FAIL;
		వెళ్ళు fail;
	}

#నిర్వచితమైతే DEBUG
	_resp->options |= RES_DEBUG;
#అయితే_ముగింపు /* DEBUG */

#నిర్వచితమైతే RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ఒకవేళ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#అయితే_ముగింపు /* RES_USE_DNSEC */

	/* make query */
	నిడివి = res_query(hostname, (గుర్తుగల పూర్ణాంకం) rdclass, (గుర్తుగల పూర్ణాంకం) rdtype,
	    answer, పరిమాణం(answer));
	ఒకవేళ (నిడివి < 0) {
		ఎంపిక(h_errno) {
		స్థితి HOST_NOT_FOUND:
			ఫలితం = ERRSET_NONAME;
			వెళ్ళు fail;
		స్థితి NO_DATA:
			ఫలితం = ERRSET_NODATA;
			వెళ్ళు fail;
		అప్రమేయ:
			ఫలితం = ERRSET_FAIL;
			వెళ్ళు fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, నిడివి);
	ఒకవేళ (response == ఖాళీ) {
		ఫలితం = ERRSET_FAIL;
		వెళ్ళు fail;
	}

	ఒకవేళ (response->శీర్షిక_3.qdcount != 1) {
		ఫలితం = ERRSET_FAIL;
		వెళ్ళు fail;
	}

	/* initialize rrset */
	rrset = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(నిర్మాణం rrsetinfo));
	ఒకవేళ (rrset == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->శీర్షిక_3.ancount;

#నిర్వచితమైతే HAVE_శీర్షిక_AD
	/* check for authenticated data */
	ఒకవేళ (response->శీర్షిక_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#అయితే_ముగింపు

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ఒకవేళ (rrset->rri_name == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}

	/* count answers */
	rrset->rri_nrdatas = లెక్క_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = లెక్క_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = సున్నా_జ్ఞాపకం_ఇవ్వు(rrset->rri_nrdatas,
	    పరిమాణం(నిర్మాణం rdatainfo));
	ఒకవేళ (rrset->rri_rdatas == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}

	/* allocate memory for signatures */
	ఒకవేళ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = సున్నా_జ్ఞాపకం_ఇవ్వు(rrset->rri_nsigs, పరిమాణం(నిర్మాణం rdatainfo));
		ఒకవేళ (rrset->rri_sigs == ఖాళీ) {
			ఫలితం = ERRSET_NOMEMORY;
			వెళ్ళు fail;
		}
	}

	/* copy answers & signatures */
	కొరకు (rr = response->answer, సూచీ_ans = 0, సూచీ_sig = 0;
	    rr; rr = rr->తదుపరి) {

		rdata = ఖాళీ;

		ఒకవేళ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[సూచీ_ans++];

		ఒకవేళ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[సూచీ_sig++];

		ఒకవేళ (rdata) {
			rdata->rdi_నిడివి = rr->కొలత;
			ఒకవేళ (rr->కొలత != 0) {
				rdata->rdi_దత్తాంశం   = జ్ఞాపకం_ఇవ్వు(rr->కొలత);
				ఒకవేళ (rdata->rdi_దత్తాంశం == ఖాళీ) {
					ఫలితం = ERRSET_NOMEMORY;
					వెళ్ళు fail;
				}
				జ్ఞాపకం_నకలు(rdata->rdi_దత్తాంశం, rr->rdata, rr->కొలత);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	తిరిగి (ERRSET_SUCCESS);

fail:
	ఒకవేళ (rrset != ఖాళీ)
		freerrset(rrset);
	ఒకవేళ (response != ఖాళీ)
		free_dns_response(response);
	తిరిగి (ఫలితం);
}

శూన్య
freerrset(నిర్మాణం rrsetinfo *rrset)
{
	u_int16_t i;

	ఒకవేళ (rrset == ఖాళీ)
		తిరిగి;

	ఒకవేళ (rrset->rri_rdatas) {
		కొరకు (i = 0; i < rrset->rri_nrdatas; i++) {
			ఒకవేళ (rrset->rri_rdatas[i].rdi_దత్తాంశం == ఖాళీ)
				ఆపు;
			విడుదల(rrset->rri_rdatas[i].rdi_దత్తాంశం);
		}
		విడుదల(rrset->rri_rdatas);
	}

	ఒకవేళ (rrset->rri_sigs) {
		కొరకు (i = 0; i < rrset->rri_nsigs; i++) {
			ఒకవేళ (rrset->rri_sigs[i].rdi_దత్తాంశం == ఖాళీ)
				ఆపు;
			విడుదల(rrset->rri_sigs[i].rdi_దత్తాంశం);
		}
		విడుదల(rrset->rri_sigs);
	}

	ఒకవేళ (rrset->rri_name)
		విడుదల(rrset->rri_name);
	విడుదల(rrset);
}

/*
 * DNS response parsing routines
 */
స్థిర నిర్మాణం dns_response *
parse_dns_response(స్థిరరాశి u_char *answer, పూర్ణాంకం కొలత)
{
	నిర్మాణం dns_response *resp;
	స్థిరరాశి u_char *cp;

	ఒకవేళ (కొలత < HFIXEDSZ)
		తిరిగి (ఖాళీ);

	/* allocate memory for the response */
	resp = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*resp));
	ఒకవేళ (resp == ఖాళీ)
		తిరిగి (ఖాళీ);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	జ్ఞాపకం_నకలు(&resp->శీర్షిక_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->శీర్షిక_3.qdcount = ntohs(resp->శీర్షిక_3.qdcount);
	resp->శీర్షిక_3.ancount = ntohs(resp->శీర్షిక_3.ancount);
	resp->శీర్షిక_3.nscount = ntohs(resp->శీర్షిక_3.nscount);
	resp->శీర్షిక_3.arcount = ntohs(resp->శీర్షిక_3.arcount);

	/* there must be at least one query */
	ఒకవేళ (resp->శీర్షిక_3.qdcount < 1) {
		free_dns_response(resp);
		తిరిగి (ఖాళీ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, కొలత, &cp,
	    resp->శీర్షిక_3.qdcount);
	ఒకవేళ (resp->శీర్షిక_3.qdcount && resp->query == ఖాళీ) {
		free_dns_response(resp);
		తిరిగి (ఖాళీ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, కొలత, &cp,
	    resp->శీర్షిక_3.ancount);
	ఒకవేళ (resp->శీర్షిక_3.ancount && resp->answer == ఖాళీ) {
		free_dns_response(resp);
		తిరిగి (ఖాళీ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, కొలత, &cp,
	    resp->శీర్షిక_3.nscount);
	ఒకవేళ (resp->శీర్షిక_3.nscount && resp->authority == ఖాళీ) {
		free_dns_response(resp);
		తిరిగి (ఖాళీ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, కొలత, &cp,
	    resp->శీర్షిక_3.arcount);
	ఒకవేళ (resp->శీర్షిక_3.arcount && resp->additional == ఖాళీ) {
		free_dns_response(resp);
		తిరిగి (ఖాళీ);
	}

	తిరిగి (resp);
}

స్థిర నిర్మాణం dns_query *
parse_dns_qsection(స్థిరరాశి u_char *answer, పూర్ణాంకం కొలత, స్థిరరాశి u_char **cp, పూర్ణాంకం లెక్క)
{
	నిర్మాణం dns_query *తల, *curr, *prev;
	పూర్ణాంకం i, నిడివి;
	అక్షరం name[MAXDNAME];

#నిర్వచించు NEED(need) \
	చేయి { \
		ఒకవేళ (*cp + need > answer + కొలత) \
			వెళ్ళు fail; \
	} అయితే (0)

	కొరకు (i = 1, తల = ఖాళీ, prev = ఖాళీ; i <= లెక్క; i++, prev = curr) {
		ఒకవేళ (*cp >= answer + కొలత) {
 fail:
			free_dns_query(తల);
			తిరిగి (ఖాళీ);
		}
		/* allocate and initialize struct */
		curr = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(నిర్మాణం dns_query));
		ఒకవేళ (curr == ఖాళీ)
			వెళ్ళు fail;
		ఒకవేళ (తల == ఖాళీ)
			తల = curr;
		ఒకవేళ (prev != ఖాళీ)
			prev->తదుపరి = curr;

		/* name */
		నిడివి = dn_expand(answer, answer + కొలత, *cp, name,
		    పరిమాణం(name));
		ఒకవేళ (నిడివి < 0) {
			free_dns_query(తల);
			తిరిగి (ఖాళీ);
		}
		curr->name = strdup(name);
		ఒకవేళ (curr->name == ఖాళీ) {
			free_dns_query(తల);
			తిరిగి (ఖాళీ);
		}
		NEED(నిడివి);
		*cp += నిడివి;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#నిర్వచనం_రద్దు NEED

	తిరిగి (తల);
}

స్థిర నిర్మాణం dns_rr *
parse_dns_rrsection(స్థిరరాశి u_char *answer, పూర్ణాంకం కొలత, స్థిరరాశి u_char **cp,
    పూర్ణాంకం లెక్క)
{
	నిర్మాణం dns_rr *తల, *curr, *prev;
	పూర్ణాంకం i, నిడివి;
	అక్షరం name[MAXDNAME];

#నిర్వచించు NEED(need) \
	చేయి { \
		ఒకవేళ (*cp + need > answer + కొలత) \
			వెళ్ళు fail; \
	} అయితే (0)

	కొరకు (i = 1, తల = ఖాళీ, prev = ఖాళీ; i <= లెక్క; i++, prev = curr) {
		ఒకవేళ (*cp >= answer + కొలత) {
 fail:
			free_dns_rr(తల);
			తిరిగి (ఖాళీ);
		}

		/* allocate and initialize struct */
		curr = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(నిర్మాణం dns_rr));
		ఒకవేళ (curr == ఖాళీ)
			వెళ్ళు fail;
		ఒకవేళ (తల == ఖాళీ)
			తల = curr;
		ఒకవేళ (prev != ఖాళీ)
			prev->తదుపరి = curr;

		/* name */
		నిడివి = dn_expand(answer, answer + కొలత, *cp, name,
		    పరిమాణం(name));
		ఒకవేళ (నిడివి < 0) {
			free_dns_rr(తల);
			తిరిగి (ఖాళీ);
		}
		curr->name = strdup(name);
		ఒకవేళ (curr->name == ఖాళీ) {
			free_dns_rr(తల);
			తిరిగి (ఖాళీ);
		}
		NEED(నిడివి);
		*cp += నిడివి;

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
		curr->కొలత = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->కొలత);
		ఒకవేళ (curr->కొలత != 0) {
			ఒకవేళ ((curr->rdata = జ్ఞాపకం_ఇవ్వు(curr->కొలత)) == ఖాళీ) {
				free_dns_rr(తల);
				తిరిగి (ఖాళీ);
			}
			జ్ఞాపకం_నకలు(curr->rdata, *cp, curr->కొలత);
		}
		*cp += curr->కొలత;
	}
#నిర్వచనం_రద్దు NEED

	తిరిగి (తల);
}

స్థిర శూన్య
free_dns_query(నిర్మాణం dns_query *p)
{
	నిర్మాణం dns_query *తదుపరి;

	అయితే (p != ఖాళీ) {
		తదుపరి = p->తదుపరి;
		విడుదల(p->name);
		విడుదల(p);
		p = తదుపరి;
	}
}

స్థిర శూన్య
free_dns_rr(నిర్మాణం dns_rr *p)
{
	నిర్మాణం dns_rr *తదుపరి;

	అయితే (p != ఖాళీ) {
		తదుపరి = p->తదుపరి;
		విడుదల(p->name);
		విడుదల(p->rdata);
		విడుదల(p);
		p = తదుపరి;
	}
}

స్థిర శూన్య
free_dns_response(నిర్మాణం dns_response *p)
{
	ఒకవేళ (p == ఖాళీ)
		తిరిగి;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	విడుదల(p);
}

స్థిర పూర్ణాంకం
లెక్క_dns_rr(నిర్మాణం dns_rr *p, u_int16_t class, u_int16_t type)
{
	పూర్ణాంకం n = 0;

	అయితే(p) {
		ఒకవేళ (p->class == class && p->type == type)
			n++;
		p = p->తదుపరి;
	}

	తిరిగి (n);
}

#అయితే_ముగింపు /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
