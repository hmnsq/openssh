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

#شامل "includes.h"

#اگر !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#شامل <stdlib.h>
#شامل <string.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل "getrrsetbyname.h"

#اگر defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
خارجی صحیح h_errno;
#اگر_ختم

/* We don't need multithread support here */
#اگر_تعریف_شدہ THREAD_نجی
# undef THREAD_نجی
#اگر_ختم
#تعریف_کرو THREAD_نجی(a,b,c) (c)

#اگر_غیر_تعریف_شدہ HAVE__RES_EXTERN
ساخت __res_state _res;
#اگر_ختم

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#اگر_غیر_تعریف_شدہ INT32SZ
# define INT32SZ	4
#اگر_ختم
#اگر_غیر_تعریف_شدہ INT16SZ
# define INT16SZ	2
#اگر_ختم

#اگر_غیر_تعریف_شدہ GETSHORT
#تعریف_کرو GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ GETLONG
#تعریف_کرو GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#اگر_ختم

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#اگر !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
ساکن u_int16_t
_getshort(ثابت u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	واپس (u);
}

ساکن u_int32_t
_getlong(ثابت u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	واپس (u);
}
#اگر_ختم /* missing _getshort/_getlong */

/* ************** */

#تعریف_کرو ANSWER_بفر_سائز 0xffff

ساخت dns_query {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	ساخت dns_query	*اگلا;
};

ساخت dns_rr {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		سائز;
	خالی			*rdata;
	ساخت dns_rr		*اگلا;
};

ساخت dns_response {
	سرخی_2			سرخی_3;
	ساخت dns_query	*query;
	ساخت dns_rr		*answer;
	ساخت dns_rr		*authority;
	ساخت dns_rr		*additional;
};

ساکن ساخت dns_response *parse_dns_response(ثابت u_char *, صحیح);
ساکن ساخت dns_query *parse_dns_qsection(ثابت u_char *, صحیح,
    ثابت u_char **, صحیح);
ساکن ساخت dns_rr *parse_dns_rrsection(ثابت u_char *, صحیح, ثابت u_char **,
    صحیح);

ساکن خالی free_dns_query(ساخت dns_query *);
ساکن خالی free_dns_rr(ساخت dns_rr *);
ساکن خالی free_dns_response(ساخت dns_response *);

ساکن صحیح گنتی_dns_rr(ساخت dns_rr *, u_int16_t, u_int16_t);

صحیح
getrrsetbyname(ثابت حرف *hostname, غیرعلامتی صحیح rdclass,
    غیرعلامتی صحیح rdtype, غیرعلامتی صحیح flags,
    ساخت rrsetinfo **res)
{
	ساخت __res_state *_resp = THREAD_نجی(_res, _res, &_res);
	صحیح نتیجہ;
	ساخت rrsetinfo *rrset = تہی;
	ساخت dns_response *response = تہی;
	ساخت dns_rr *rr;
	ساخت rdatainfo *rdata;
	صحیح لمبائی;
	غیرعلامتی صحیح اشاریہ_ans, اشاریہ_sig;
	u_char answer[ANSWER_بفر_سائز];

	/* check for invalid class and type */
	اگر (rdclass > 0xffff || rdtype > 0xffff) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* don't allow queries of class or type ANY */
	اگر (rdclass == 0xff || rdtype == 0xff) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* don't allow flags yet, unimplemented */
	اگر (flags) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* initialize resolver */
	اگر ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		نتیجہ = ERRSET_FAIL;
		جاؤ fail;
	}

#اگر_تعریف_شدہ DEBUG
	_resp->options |= RES_DEBUG;
#اگر_ختم /* DEBUG */

#اگر_تعریف_شدہ RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	اگر (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#اگر_ختم /* RES_USE_DNSEC */

	/* make query */
	لمبائی = res_query(hostname, (علامتی صحیح) rdclass, (علامتی صحیح) rdtype,
	    answer, حجم(answer));
	اگر (لمبائی < 0) {
		انتخاب(h_errno) {
		حالت HOST_NOT_FOUND:
			نتیجہ = ERRSET_NONAME;
			جاؤ fail;
		حالت NO_DATA:
			نتیجہ = ERRSET_NODATA;
			جاؤ fail;
		طےشدہ:
			نتیجہ = ERRSET_FAIL;
			جاؤ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, لمبائی);
	اگر (response == تہی) {
		نتیجہ = ERRSET_FAIL;
		جاؤ fail;
	}

	اگر (response->سرخی_3.qdcount != 1) {
		نتیجہ = ERRSET_FAIL;
		جاؤ fail;
	}

	/* initialize rrset */
	rrset = صفر_حافظہ_دو(1, حجم(ساخت rrsetinfo));
	اگر (rrset == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->سرخی_3.ancount;

#اگر_تعریف_شدہ HAVE_سرخی_AD
	/* check for authenticated data */
	اگر (response->سرخی_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#اگر_ختم

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	اگر (rrset->rri_name == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = گنتی_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = گنتی_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = صفر_حافظہ_دو(rrset->rri_nrdatas,
	    حجم(ساخت rdatainfo));
	اگر (rrset->rri_rdatas == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}

	/* allocate memory for signatures */
	اگر (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = صفر_حافظہ_دو(rrset->rri_nsigs, حجم(ساخت rdatainfo));
		اگر (rrset->rri_sigs == تہی) {
			نتیجہ = ERRSET_NOMEMORY;
			جاؤ fail;
		}
	}

	/* copy answers & signatures */
	برائے (rr = response->answer, اشاریہ_ans = 0, اشاریہ_sig = 0;
	    rr; rr = rr->اگلا) {

		rdata = تہی;

		اگر (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[اشاریہ_ans++];

		اگر (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[اشاریہ_sig++];

		اگر (rdata) {
			rdata->rdi_لمبائی = rr->سائز;
			اگر (rr->سائز != 0) {
				rdata->rdi_ڈیٹا   = حافظہ_دو(rr->سائز);
				اگر (rdata->rdi_ڈیٹا == تہی) {
					نتیجہ = ERRSET_NOMEMORY;
					جاؤ fail;
				}
				حافظہ_نقل(rdata->rdi_ڈیٹا, rr->rdata, rr->سائز);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	واپس (ERRSET_SUCCESS);

fail:
	اگر (rrset != تہی)
		freerrset(rrset);
	اگر (response != تہی)
		free_dns_response(response);
	واپس (نتیجہ);
}

خالی
freerrset(ساخت rrsetinfo *rrset)
{
	u_int16_t i;

	اگر (rrset == تہی)
		واپس;

	اگر (rrset->rri_rdatas) {
		برائے (i = 0; i < rrset->rri_nrdatas; i++) {
			اگر (rrset->rri_rdatas[i].rdi_ڈیٹا == تہی)
				توڑو;
			آزاد(rrset->rri_rdatas[i].rdi_ڈیٹا);
		}
		آزاد(rrset->rri_rdatas);
	}

	اگر (rrset->rri_sigs) {
		برائے (i = 0; i < rrset->rri_nsigs; i++) {
			اگر (rrset->rri_sigs[i].rdi_ڈیٹا == تہی)
				توڑو;
			آزاد(rrset->rri_sigs[i].rdi_ڈیٹا);
		}
		آزاد(rrset->rri_sigs);
	}

	اگر (rrset->rri_name)
		آزاد(rrset->rri_name);
	آزاد(rrset);
}

/*
 * DNS response parsing routines
 */
ساکن ساخت dns_response *
parse_dns_response(ثابت u_char *answer, صحیح سائز)
{
	ساخت dns_response *resp;
	ثابت u_char *cp;

	اگر (سائز < HFIXEDSZ)
		واپس (تہی);

	/* allocate memory for the response */
	resp = صفر_حافظہ_دو(1, حجم(*resp));
	اگر (resp == تہی)
		واپس (تہی);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	حافظہ_نقل(&resp->سرخی_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->سرخی_3.qdcount = ntohs(resp->سرخی_3.qdcount);
	resp->سرخی_3.ancount = ntohs(resp->سرخی_3.ancount);
	resp->سرخی_3.nscount = ntohs(resp->سرخی_3.nscount);
	resp->سرخی_3.arcount = ntohs(resp->سرخی_3.arcount);

	/* there must be at least one query */
	اگر (resp->سرخی_3.qdcount < 1) {
		free_dns_response(resp);
		واپس (تہی);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, سائز, &cp,
	    resp->سرخی_3.qdcount);
	اگر (resp->سرخی_3.qdcount && resp->query == تہی) {
		free_dns_response(resp);
		واپس (تہی);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, سائز, &cp,
	    resp->سرخی_3.ancount);
	اگر (resp->سرخی_3.ancount && resp->answer == تہی) {
		free_dns_response(resp);
		واپس (تہی);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, سائز, &cp,
	    resp->سرخی_3.nscount);
	اگر (resp->سرخی_3.nscount && resp->authority == تہی) {
		free_dns_response(resp);
		واپس (تہی);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, سائز, &cp,
	    resp->سرخی_3.arcount);
	اگر (resp->سرخی_3.arcount && resp->additional == تہی) {
		free_dns_response(resp);
		واپس (تہی);
	}

	واپس (resp);
}

ساکن ساخت dns_query *
parse_dns_qsection(ثابت u_char *answer, صحیح سائز, ثابت u_char **cp, صحیح گنتی)
{
	ساخت dns_query *سر, *curr, *پچھلا;
	صحیح i, لمبائی;
	حرف name[MAXDNAME];

#تعریف_کرو NEED(need) \
	کرو { \
		اگر (*cp + need > answer + سائز) \
			جاؤ fail; \
	} جب (0)

	برائے (i = 1, سر = تہی, پچھلا = تہی; i <= گنتی; i++, پچھلا = curr) {
		اگر (*cp >= answer + سائز) {
 fail:
			free_dns_query(سر);
			واپس (تہی);
		}
		/* allocate and initialize struct */
		curr = صفر_حافظہ_دو(1, حجم(ساخت dns_query));
		اگر (curr == تہی)
			جاؤ fail;
		اگر (سر == تہی)
			سر = curr;
		اگر (پچھلا != تہی)
			پچھلا->اگلا = curr;

		/* name */
		لمبائی = dn_expand(answer, answer + سائز, *cp, name,
		    حجم(name));
		اگر (لمبائی < 0) {
			free_dns_query(سر);
			واپس (تہی);
		}
		curr->name = strdup(name);
		اگر (curr->name == تہی) {
			free_dns_query(سر);
			واپس (تہی);
		}
		NEED(لمبائی);
		*cp += لمبائی;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#تعریف_منسوخ NEED

	واپس (سر);
}

ساکن ساخت dns_rr *
parse_dns_rrsection(ثابت u_char *answer, صحیح سائز, ثابت u_char **cp,
    صحیح گنتی)
{
	ساخت dns_rr *سر, *curr, *پچھلا;
	صحیح i, لمبائی;
	حرف name[MAXDNAME];

#تعریف_کرو NEED(need) \
	کرو { \
		اگر (*cp + need > answer + سائز) \
			جاؤ fail; \
	} جب (0)

	برائے (i = 1, سر = تہی, پچھلا = تہی; i <= گنتی; i++, پچھلا = curr) {
		اگر (*cp >= answer + سائز) {
 fail:
			free_dns_rr(سر);
			واپس (تہی);
		}

		/* allocate and initialize struct */
		curr = صفر_حافظہ_دو(1, حجم(ساخت dns_rr));
		اگر (curr == تہی)
			جاؤ fail;
		اگر (سر == تہی)
			سر = curr;
		اگر (پچھلا != تہی)
			پچھلا->اگلا = curr;

		/* name */
		لمبائی = dn_expand(answer, answer + سائز, *cp, name,
		    حجم(name));
		اگر (لمبائی < 0) {
			free_dns_rr(سر);
			واپس (تہی);
		}
		curr->name = strdup(name);
		اگر (curr->name == تہی) {
			free_dns_rr(سر);
			واپس (تہی);
		}
		NEED(لمبائی);
		*cp += لمبائی;

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
		curr->سائز = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->سائز);
		اگر (curr->سائز != 0) {
			اگر ((curr->rdata = حافظہ_دو(curr->سائز)) == تہی) {
				free_dns_rr(سر);
				واپس (تہی);
			}
			حافظہ_نقل(curr->rdata, *cp, curr->سائز);
		}
		*cp += curr->سائز;
	}
#تعریف_منسوخ NEED

	واپس (سر);
}

ساکن خالی
free_dns_query(ساخت dns_query *p)
{
	ساخت dns_query *اگلا;

	جب (p != تہی) {
		اگلا = p->اگلا;
		آزاد(p->name);
		آزاد(p);
		p = اگلا;
	}
}

ساکن خالی
free_dns_rr(ساخت dns_rr *p)
{
	ساخت dns_rr *اگلا;

	جب (p != تہی) {
		اگلا = p->اگلا;
		آزاد(p->name);
		آزاد(p->rdata);
		آزاد(p);
		p = اگلا;
	}
}

ساکن خالی
free_dns_response(ساخت dns_response *p)
{
	اگر (p == تہی)
		واپس;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	آزاد(p);
}

ساکن صحیح
گنتی_dns_rr(ساخت dns_rr *p, u_int16_t class, u_int16_t type)
{
	صحیح n = 0;

	جب(p) {
		اگر (p->class == class && p->type == type)
			n++;
		p = p->اگلا;
	}

	واپس (n);
}

#اگر_ختم /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
