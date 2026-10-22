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
#جيڪڏهن_پورو

/* We don't need multithread support here */
#جيڪڏهن_وصف_ٿيل THREAD_ذاتي
# undef THREAD_ذاتي
#جيڪڏهن_پورو
#وصف_ڪريو THREAD_ذاتي(a,b,c) (c)

#جيڪڏهن_وصف_نه_ٿيل HAVE__RES_EXTERN
بنية __res_state _res;
#جيڪڏهن_پورو

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#جيڪڏهن_وصف_نه_ٿيل INT32SZ
# define INT32SZ	4
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل INT16SZ
# define INT16SZ	2
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل GETSHORT
#وصف_ڪريو GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل GETLONG
#وصف_ڪريو GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#جيڪڏهن_پورو

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
#جيڪڏهن_پورو /* missing _getshort/_getlong */

/* ************** */

#وصف_ڪريو ANSWER_بفر_سائيز 0xffff

بنية dns_query {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	بنية dns_query	*ايندڙ;
};

بنية dns_rr {
	حرف			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		سائيز;
	فراغ			*rdata;
	بنية dns_rr		*ايندڙ;
};

بنية dns_response {
	سرو_2			سرو_3;
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

ساكن صحيح ڳڻپ_dns_rr(بنية dns_rr *, u_int16_t, u_int16_t);

صحيح
getrrsetbyname(ثابت حرف *hostname, بنانشان صحيح rdclass,
    بنانشان صحيح rdtype, بنانشان صحيح flags,
    بنية rrsetinfo **res)
{
	بنية __res_state *_resp = THREAD_ذاتي(_res, _res, &_res);
	صحيح نتيجو;
	بنية rrsetinfo *rrset = عدم;
	بنية dns_response *response = عدم;
	بنية dns_rr *rr;
	بنية rdatainfo *rdata;
	صحيح ڊيگهائي;
	بنانشان صحيح اشاريو_ans, اشاريو_sig;
	u_char answer[ANSWER_بفر_سائيز];

	/* check for invalid class and type */
	إذا (rdclass > 0xffff || rdtype > 0xffff) {
		نتيجو = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow queries of class or type ANY */
	إذا (rdclass == 0xff || rdtype == 0xff) {
		نتيجو = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow flags yet, unimplemented */
	إذا (flags) {
		نتيجو = ERRSET_INVAL;
		اذهب fail;
	}

	/* initialize resolver */
	إذا ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		نتيجو = ERRSET_FAIL;
		اذهب fail;
	}

#جيڪڏهن_وصف_ٿيل DEBUG
	_resp->options |= RES_DEBUG;
#جيڪڏهن_پورو /* DEBUG */

#جيڪڏهن_وصف_ٿيل RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	إذا (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#جيڪڏهن_پورو /* RES_USE_DNSEC */

	/* make query */
	ڊيگهائي = res_query(hostname, (نشانوارو صحيح) rdclass, (نشانوارو صحيح) rdtype,
	    answer, حجم(answer));
	إذا (ڊيگهائي < 0) {
		بدل(h_errno) {
		حالة HOST_NOT_FOUND:
			نتيجو = ERRSET_NONAME;
			اذهب fail;
		حالة NO_DATA:
			نتيجو = ERRSET_NODATA;
			اذهب fail;
		افتراضي:
			نتيجو = ERRSET_FAIL;
			اذهب fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, ڊيگهائي);
	إذا (response == عدم) {
		نتيجو = ERRSET_FAIL;
		اذهب fail;
	}

	إذا (response->سرو_3.qdcount != 1) {
		نتيجو = ERRSET_FAIL;
		اذهب fail;
	}

	/* initialize rrset */
	rrset = صفر_يادگيري_ڏيو(1, حجم(بنية rrsetinfo));
	إذا (rrset == عدم) {
		نتيجو = ERRSET_NOMEMORY;
		اذهب fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->سرو_3.ancount;

#جيڪڏهن_وصف_ٿيل HAVE_سرو_AD
	/* check for authenticated data */
	إذا (response->سرو_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#جيڪڏهن_پورو

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	إذا (rrset->rri_name == عدم) {
		نتيجو = ERRSET_NOMEMORY;
		اذهب fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ڳڻپ_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ڳڻپ_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = صفر_يادگيري_ڏيو(rrset->rri_nrdatas,
	    حجم(بنية rdatainfo));
	إذا (rrset->rri_rdatas == عدم) {
		نتيجو = ERRSET_NOMEMORY;
		اذهب fail;
	}

	/* allocate memory for signatures */
	إذا (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = صفر_يادگيري_ڏيو(rrset->rri_nsigs, حجم(بنية rdatainfo));
		إذا (rrset->rri_sigs == عدم) {
			نتيجو = ERRSET_NOMEMORY;
			اذهب fail;
		}
	}

	/* copy answers & signatures */
	لكل (rr = response->answer, اشاريو_ans = 0, اشاريو_sig = 0;
	    rr; rr = rr->ايندڙ) {

		rdata = عدم;

		إذا (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[اشاريو_ans++];

		إذا (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[اشاريو_sig++];

		إذا (rdata) {
			rdata->rdi_ڊيگهائي = rr->سائيز;
			إذا (rr->سائيز != 0) {
				rdata->rdi_معلومات   = يادگيري_ڏيو(rr->سائيز);
				إذا (rdata->rdi_معلومات == عدم) {
					نتيجو = ERRSET_NOMEMORY;
					اذهب fail;
				}
				يادگيري_نقل(rdata->rdi_معلومات, rr->rdata, rr->سائيز);
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
	أرجع (نتيجو);
}

فراغ
freerrset(بنية rrsetinfo *rrset)
{
	u_int16_t i;

	إذا (rrset == عدم)
		أرجع;

	إذا (rrset->rri_rdatas) {
		لكل (i = 0; i < rrset->rri_nrdatas; i++) {
			إذا (rrset->rri_rdatas[i].rdi_معلومات == عدم)
				اكسر;
			حرر(rrset->rri_rdatas[i].rdi_معلومات);
		}
		حرر(rrset->rri_rdatas);
	}

	إذا (rrset->rri_sigs) {
		لكل (i = 0; i < rrset->rri_nsigs; i++) {
			إذا (rrset->rri_sigs[i].rdi_معلومات == عدم)
				اكسر;
			حرر(rrset->rri_sigs[i].rdi_معلومات);
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
parse_dns_response(ثابت u_char *answer, صحيح سائيز)
{
	بنية dns_response *resp;
	ثابت u_char *cp;

	إذا (سائيز < HFIXEDSZ)
		أرجع (عدم);

	/* allocate memory for the response */
	resp = صفر_يادگيري_ڏيو(1, حجم(*resp));
	إذا (resp == عدم)
		أرجع (عدم);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	يادگيري_نقل(&resp->سرو_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->سرو_3.qdcount = ntohs(resp->سرو_3.qdcount);
	resp->سرو_3.ancount = ntohs(resp->سرو_3.ancount);
	resp->سرو_3.nscount = ntohs(resp->سرو_3.nscount);
	resp->سرو_3.arcount = ntohs(resp->سرو_3.arcount);

	/* there must be at least one query */
	إذا (resp->سرو_3.qdcount < 1) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, سائيز, &cp,
	    resp->سرو_3.qdcount);
	إذا (resp->سرو_3.qdcount && resp->query == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, سائيز, &cp,
	    resp->سرو_3.ancount);
	إذا (resp->سرو_3.ancount && resp->answer == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, سائيز, &cp,
	    resp->سرو_3.nscount);
	إذا (resp->سرو_3.nscount && resp->authority == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, سائيز, &cp,
	    resp->سرو_3.arcount);
	إذا (resp->سرو_3.arcount && resp->additional == عدم) {
		free_dns_response(resp);
		أرجع (عدم);
	}

	أرجع (resp);
}

ساكن بنية dns_query *
parse_dns_qsection(ثابت u_char *answer, صحيح سائيز, ثابت u_char **cp, صحيح ڳڻپ)
{
	بنية dns_query *سر, *curr, *prev;
	صحيح i, ڊيگهائي;
	حرف name[MAXDNAME];

#وصف_ڪريو NEED(need) \
	افعل { \
		إذا (*cp + need > answer + سائيز) \
			اذهب fail; \
	} طالما (0)

	لكل (i = 1, سر = عدم, prev = عدم; i <= ڳڻپ; i++, prev = curr) {
		إذا (*cp >= answer + سائيز) {
 fail:
			free_dns_query(سر);
			أرجع (عدم);
		}
		/* allocate and initialize struct */
		curr = صفر_يادگيري_ڏيو(1, حجم(بنية dns_query));
		إذا (curr == عدم)
			اذهب fail;
		إذا (سر == عدم)
			سر = curr;
		إذا (prev != عدم)
			prev->ايندڙ = curr;

		/* name */
		ڊيگهائي = dn_expand(answer, answer + سائيز, *cp, name,
		    حجم(name));
		إذا (ڊيگهائي < 0) {
			free_dns_query(سر);
			أرجع (عدم);
		}
		curr->name = strdup(name);
		إذا (curr->name == عدم) {
			free_dns_query(سر);
			أرجع (عدم);
		}
		NEED(ڊيگهائي);
		*cp += ڊيگهائي;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#وصف_رد NEED

	أرجع (سر);
}

ساكن بنية dns_rr *
parse_dns_rrsection(ثابت u_char *answer, صحيح سائيز, ثابت u_char **cp,
    صحيح ڳڻپ)
{
	بنية dns_rr *سر, *curr, *prev;
	صحيح i, ڊيگهائي;
	حرف name[MAXDNAME];

#وصف_ڪريو NEED(need) \
	افعل { \
		إذا (*cp + need > answer + سائيز) \
			اذهب fail; \
	} طالما (0)

	لكل (i = 1, سر = عدم, prev = عدم; i <= ڳڻپ; i++, prev = curr) {
		إذا (*cp >= answer + سائيز) {
 fail:
			free_dns_rr(سر);
			أرجع (عدم);
		}

		/* allocate and initialize struct */
		curr = صفر_يادگيري_ڏيو(1, حجم(بنية dns_rr));
		إذا (curr == عدم)
			اذهب fail;
		إذا (سر == عدم)
			سر = curr;
		إذا (prev != عدم)
			prev->ايندڙ = curr;

		/* name */
		ڊيگهائي = dn_expand(answer, answer + سائيز, *cp, name,
		    حجم(name));
		إذا (ڊيگهائي < 0) {
			free_dns_rr(سر);
			أرجع (عدم);
		}
		curr->name = strdup(name);
		إذا (curr->name == عدم) {
			free_dns_rr(سر);
			أرجع (عدم);
		}
		NEED(ڊيگهائي);
		*cp += ڊيگهائي;

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
		curr->سائيز = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->سائيز);
		إذا (curr->سائيز != 0) {
			إذا ((curr->rdata = يادگيري_ڏيو(curr->سائيز)) == عدم) {
				free_dns_rr(سر);
				أرجع (عدم);
			}
			يادگيري_نقل(curr->rdata, *cp, curr->سائيز);
		}
		*cp += curr->سائيز;
	}
#وصف_رد NEED

	أرجع (سر);
}

ساكن فراغ
free_dns_query(بنية dns_query *p)
{
	بنية dns_query *ايندڙ;

	طالما (p != عدم) {
		ايندڙ = p->ايندڙ;
		حرر(p->name);
		حرر(p);
		p = ايندڙ;
	}
}

ساكن فراغ
free_dns_rr(بنية dns_rr *p)
{
	بنية dns_rr *ايندڙ;

	طالما (p != عدم) {
		ايندڙ = p->ايندڙ;
		حرر(p->name);
		حرر(p->rdata);
		حرر(p);
		p = ايندڙ;
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
ڳڻپ_dns_rr(بنية dns_rr *p, u_int16_t class, u_int16_t type)
{
	صحيح n = 0;

	طالما(p) {
		إذا (p->class == class && p->type == type)
			n++;
		p = p->ايندڙ;
	}

	أرجع (n);
}

#جيڪڏهن_پورو /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
