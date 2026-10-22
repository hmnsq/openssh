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

#ضمن "includes.h"

#إذا !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن "getrrsetbyname.h"

#إذا defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
خارجي صحيح h_errno;
#جے_انت

/* We don't need multithread support here */
#جے_تعریف_شدہ THREAD_نجی
# undef THREAD_نجی
#جے_انت
#تعریف_کرو THREAD_نجی(a,b,c) (c)

#جے_بنا_تعریف HAVE__RES_EXTERN
بنية __res_state _res;
#جے_انت

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#جے_بنا_تعریف INT32SZ
# define INT32SZ	4
#جے_انت
#جے_بنا_تعریف INT16SZ
# define INT16SZ	2
#جے_انت

#جے_بنا_تعریف GETSHORT
#تعریف_کرو GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#جے_انت

#جے_بنا_تعریف GETLONG
#تعریف_کرو GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#جے_انت

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#إذا !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
ساكن u_int16_t
_getshort(ثابت u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	أرجع (u);
}

ساكن u_int32_t
_getlong(ثابت u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	أرجع (u);
}
#جے_انت /* missing _getshort/_getlong */

/* ************** */

#تعریف_کرو ANSWER_بفر_ناپ 0xffff

بنية dns_query {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	بنية dns_query	*اگلا;
};

بنية dns_rr {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		ناپ;
	فراغ			*rdata;
	بنية dns_rr		*اگلا;
};

بنية dns_response {
	سرخی_2			سرخی_3;
	بنية dns_query	*query;
	بنية dns_rr		*answer;
	بنية dns_rr		*authority;
	بنية dns_rr		*additional;
};

ساكن بنية dns_response *parse_dns_response(ثابت u_char *, صحيح);
ساكن بنية dns_query *parse_dns_qsection(ثابت u_char *, صحيح,
    ثابت u_char **, صحيح);
ساكن بنية dns_rr *parse_dns_rrsection(ثابت u_char *, صحيح, ثابت u_char **,
    صحيح);

ساكن فراغ free_dns_query(بنية dns_query *);
ساكن فراغ free_dns_rr(بنية dns_rr *);
ساكن فراغ free_dns_response(بنية dns_response *);

ساكن صحيح گنتی_dns_rr(بنية dns_rr *, u_int16_t, u_int16_t);

صحيح
getrrsetbyname(ثابت حرف *hostname, بنانشانی صحيح rdclass,
    بنانشانی صحيح rdtype, بنانشانی صحيح flags,
    بنية rrsetinfo **res)
{
	بنية __res_state *_resp = THREAD_نجی(_res, _res, &_res);
	صحيح نتیجہ;
	بنية rrsetinfo *rrset = عدم;
	بنية dns_response *response = عدم;
	بنية dns_rr *rr;
	بنية rdatainfo *rdata;
	صحيح لمائی;
	بنانشانی صحيح اشاریہ_ans, اشاریہ_sig;
	u_char answer[ANSWER_بفر_ناپ];

	/* check for invalid class and type */
	إذا (rdclass > 0xffff || rdtype > 0xffff) {
		نتیجہ = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow queries of class or type ANY */
	إذا (rdclass == 0xff || rdtype == 0xff) {
		نتیجہ = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow flags yet, unimplemented */
	إذا (flags) {
		نتیجہ = ERRSET_INVAL;
		اذهب fail;
	}

	/* initialize resolver */
	إذا ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		نتیجہ = ERRSET_FAIL;
		اذهب fail;
	}

#جے_تعریف_شدہ DEBUG
	_resp->options |= RES_DEBUG;
#جے_انت /* DEBUG */

#جے_تعریف_شدہ RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	إذا (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#جے_انت /* RES_USE_DNSEC */

	/* make query */
	لمائی = res_query(hostname, (نشانیوالا صحيح) rdclass, (نشانیوالا صحيح) rdtype,
	    answer, حجم(answer));
	إذا (لمائی < 0) {
		بدل(h_errno) {
		حالة HOST_NOT_FOUND:
			نتیجہ = ERRSET_NONAME;
			اذهب fail;
		حالة NO_DATA:
			نتیجہ = ERRSET_NODATA;
			اذهب fail;
		افتراضي:
			نتیجہ = ERRSET_FAIL;
			اذهب fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, لمائی);
	إذا (response == عدم) {
		نتیجہ = ERRSET_FAIL;
		اذهب fail;
	}

	إذا (response->سرخی_3.qdcount != 1) {
		نتیجہ = ERRSET_FAIL;
		اذهب fail;
	}

	/* initialize rrset */
	rrset = صفر_حافظہ_دیو(1, حجم(بنية rrsetinfo));
	إذا (rrset == عدم) {
		نتیجہ = ERRSET_NOMEMORY;
		اذهب fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->سرخی_3.ancount;

#جے_تعریف_شدہ HAVE_سرخی_AD
	/* check for authenticated data */
	إذا (response->سرخی_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#جے_انت

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	إذا (rrset->rri_name == عدم) {
		نتیجہ = ERRSET_NOMEMORY;
		اذهب fail;
	}

	/* count answers */
	rrset->rri_nrdatas = گنتی_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = گنتی_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = صفر_حافظہ_دیو(rrset->rri_nrdatas,
	    حجم(بنية rdatainfo));
	إذا (rrset->rri_rdatas == عدم) {
		نتیجہ = ERRSET_NOMEMORY;
		اذهب fail;
	}

	/* allocate memory for signatures */
	إذا (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = صفر_حافظہ_دیو(rrset->rri_nsigs, حجم(بنية rdatainfo));
		إذا (rrset->rri_sigs == عدم) {
			نتیجہ = ERRSET_NOMEMORY;
			اذهب fail;
		}
	}

	/* copy answers & signatures */
	لكل (rr = response->answer, اشاریہ_ans = 0, اشاریہ_sig = 0;
	    rr; rr = rr->اگلا) {

		rdata = عدم;

		إذا (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[اشاریہ_ans++];

		إذا (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[اشاریہ_sig++];

		إذا (rdata) {
			rdata->rdi_لمائی = rr->ناپ;
			إذا (rr->ناپ != 0) {
				rdata->rdi_انکڑے   = حافظہ_دیو(rr->ناپ);
				إذا (rdata->rdi_انکڑے == عدم) {
					نتیجہ = ERRSET_NOMEMORY;
					اذهب fail;
				}
				حافظہ_نقل(rdata->rdi_انکڑے, rr->rdata, rr->ناپ);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	أرجع (ERRSET_SUCCESS);

fail:
	إذا (rrset != عدم)
		freerrset(rrset);
	إذا (response != عدم)
		free_dns_response(response);
	أرجع (نتیجہ);
}

فراغ
freerrset(بنية rrsetinfo *rrset)
{
	u_int16_t i;

	إذا (rrset == عدم)
		أرجع;

	إذا (rrset->rri_rdatas) {
		لكل (i = 0; i < rrset->rri_nrdatas; i++) {
			إذا (rrset->rri_rdatas[i].rdi_انکڑے == عدم)
				اكسر;
			حرر(rrset->rri_rdatas[i].rdi_انکڑے);
		}
		حرر(rrset->rri_rdatas);
	}

	إذا (rrset->rri_sigs) {
		لكل (i = 0; i < rrset->rri_nsigs; i++) {
			إذا (rrset->rri_sigs[i].rdi_انکڑے == عدم)
				اكسر;
			حرر(rrset->rri_sigs[i].rdi_انکڑے);
		}
		حرر(rrset->rri_sigs);
	}

	إذا (rrset->rri_name)
		حرر(rrset->rri_name);
	حرر(rrset);
}

/*
 * DNS response parsing routines
 */
ساكن بنية dns_response *
parse_dns_response(ثابت u_char *answer, صحيح ناپ)
{
	بنية dns_response *resp;
	ثابت u_char *cp;

	إذا (ناپ < HFIXEDSZ)
		أرجع (عدم);

	/* allocate memory for the response */
	resp = صفر_حافظہ_دیو(1, حجم(*resp));
	إذا (resp == عدم)
		أرجع (عدم);

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
	إذا (resp->سرخی_3.qdcount < 1) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, ناپ, &cp,
	    resp->سرخی_3.qdcount);
	إذا (resp->سرخی_3.qdcount && resp->query == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, ناپ, &cp,
	    resp->سرخی_3.ancount);
	إذا (resp->سرخی_3.ancount && resp->answer == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, ناپ, &cp,
	    resp->سرخی_3.nscount);
	إذا (resp->سرخی_3.nscount && resp->authority == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, ناپ, &cp,
	    resp->سرخی_3.arcount);
	إذا (resp->سرخی_3.arcount && resp->additional == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	أرجع (resp);
}

ساكن بنية dns_query *
parse_dns_qsection(ثابت u_char *answer, صحيح ناپ, ثابت u_char **cp, صحيح گنتی)
{
	بنية dns_query *سر, *curr, *prev;
	صحيح i, لمائی;
	حرف name[MAXDNAME];

#تعریف_کرو NEED(need) \
	افعل { \
		إذا (*cp + need > answer + ناپ) \
			اذهب fail; \
	} طالما (0)

	لكل (i = 1, سر = عدم, prev = عدم; i <= گنتی; i++, prev = curr) {
		إذا (*cp >= answer + ناپ) {
 fail:
			free_dns_query(سر);
			أرجع (عدم);
		}
		/* allocate and initialize struct */
		curr = صفر_حافظہ_دیو(1, حجم(بنية dns_query));
		إذا (curr == عدم)
			اذهب fail;
		إذا (سر == عدم)
			سر = curr;
		إذا (prev != عدم)
			prev->اگلا = curr;

		/* name */
		لمائی = dn_expand(answer, answer + ناپ, *cp, name,
		    حجم(name));
		إذا (لمائی < 0) {
			free_dns_query(سر);
			أرجع (عدم);
		}
		curr->name = strdup(name);
		إذا (curr->name == عدم) {
			free_dns_query(سر);
			أرجع (عدم);
		}
		NEED(لمائی);
		*cp += لمائی;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#تعریف_رد NEED

	أرجع (سر);
}

ساكن بنية dns_rr *
parse_dns_rrsection(ثابت u_char *answer, صحيح ناپ, ثابت u_char **cp,
    صحيح گنتی)
{
	بنية dns_rr *سر, *curr, *prev;
	صحيح i, لمائی;
	حرف name[MAXDNAME];

#تعریف_کرو NEED(need) \
	افعل { \
		إذا (*cp + need > answer + ناپ) \
			اذهب fail; \
	} طالما (0)

	لكل (i = 1, سر = عدم, prev = عدم; i <= گنتی; i++, prev = curr) {
		إذا (*cp >= answer + ناپ) {
 fail:
			free_dns_rr(سر);
			أرجع (عدم);
		}

		/* allocate and initialize struct */
		curr = صفر_حافظہ_دیو(1, حجم(بنية dns_rr));
		إذا (curr == عدم)
			اذهب fail;
		إذا (سر == عدم)
			سر = curr;
		إذا (prev != عدم)
			prev->اگلا = curr;

		/* name */
		لمائی = dn_expand(answer, answer + ناپ, *cp, name,
		    حجم(name));
		إذا (لمائی < 0) {
			free_dns_rr(سر);
			أرجع (عدم);
		}
		curr->name = strdup(name);
		إذا (curr->name == عدم) {
			free_dns_rr(سر);
			أرجع (عدم);
		}
		NEED(لمائی);
		*cp += لمائی;

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
		curr->ناپ = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->ناپ);
		إذا (curr->ناپ != 0) {
			إذا ((curr->rdata = حافظہ_دیو(curr->ناپ)) == عدم) {
				free_dns_rr(سر);
				أرجع (عدم);
			}
			حافظہ_نقل(curr->rdata, *cp, curr->ناپ);
		}
		*cp += curr->ناپ;
	}
#تعریف_رد NEED

	أرجع (سر);
}

ساكن فراغ
free_dns_query(بنية dns_query *p)
{
	بنية dns_query *اگلا;

	طالما (p != عدم) {
		اگلا = p->اگلا;
		حرر(p->name);
		حرر(p);
		p = اگلا;
	}
}

ساكن فراغ
free_dns_rr(بنية dns_rr *p)
{
	بنية dns_rr *اگلا;

	طالما (p != عدم) {
		اگلا = p->اگلا;
		حرر(p->name);
		حرر(p->rdata);
		حرر(p);
		p = اگلا;
	}
}

ساكن فراغ
free_dns_response(بنية dns_response *p)
{
	إذا (p == عدم)
		أرجع;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	حرر(p);
}

ساكن صحيح
گنتی_dns_rr(بنية dns_rr *p, u_int16_t class, u_int16_t type)
{
	صحيح n = 0;

	طالما(p) {
		إذا (p->class == class && p->type == type)
			n++;
		p = p->اگلا;
	}

	أرجع (n);
}

#جے_انت /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
