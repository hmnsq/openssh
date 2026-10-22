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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS)

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "getrrsetbyname.h"

#ਜੇ defined(HAVE_DECL_H_ERRNO) && !HAVE_DECL_H_ERRNO
ਬਾਹਰੀ ਪੂਰਨ h_errno;
#ਜੇ_ਅੰਤ

/* We don't need multithread support here */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ THREAD_ਨਿੱਜੀ
# undef THREAD_ਨਿੱਜੀ
#ਜੇ_ਅੰਤ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ THREAD_ਨਿੱਜੀ(a,b,c) (c)

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE__RES_EXTERN
ਬਣਤਰ __res_state _res;
#ਜੇ_ਅੰਤ

/* Necessary functions and macros */

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 *
 * These macros demonstrate the property of C whereby it can be
 * portable or it can be elegant but rarely both.
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INT32SZ
# define INT32SZ	4
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INT16SZ
# define INT16SZ	2
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ GETSHORT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GETSHORT(s, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ GETLONG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ GETLONG(l, cp) { \
	u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
}
#ਜੇ_ਅੰਤ

/*
 * If the system doesn't have _getshort/_getlong or that are not exactly what
 * we need then use local replacements, avoiding name collisions.
 */
#ਜੇ !defined(HAVE__GETSHORT) || !defined(HAVE__GETLONG) || \
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
ਸਥਿਰ u_int16_t
_getshort(ਅਚਲ u_char *msgp)
{
	u_int16_t u;

	GETSHORT(u, msgp);
	ਵਾਪਸ (u);
}

ਸਥਿਰ u_int32_t
_getlong(ਅਚਲ u_char *msgp)
{
	u_int32_t u;

	GETLONG(u, msgp);
	ਵਾਪਸ (u);
}
#ਜੇ_ਅੰਤ /* missing _getshort/_getlong */

/* ************** */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ANSWER_ਬਫਰ_ਮਾਪ 0xffff

ਬਣਤਰ dns_query {
	ਅੱਖਰ			*name;
	u_int16_t		type;
	u_int16_t		class;
	ਬਣਤਰ dns_query	*ਅਗਲਾ;
};

ਬਣਤਰ dns_rr {
	ਅੱਖਰ			*name;
	u_int16_t		type;
	u_int16_t		class;
	u_int16_t		ttl;
	u_int16_t		ਮਾਪ;
	ਖਾਲੀ			*rdata;
	ਬਣਤਰ dns_rr		*ਅਗਲਾ;
};

ਬਣਤਰ dns_response {
	ਸਿਰਲੇਖ_2			ਸਿਰਲੇਖ_3;
	ਬਣਤਰ dns_query	*query;
	ਬਣਤਰ dns_rr		*answer;
	ਬਣਤਰ dns_rr		*authority;
	ਬਣਤਰ dns_rr		*additional;
};

ਸਥਿਰ ਬਣਤਰ dns_response *parse_dns_response(ਅਚਲ u_char *, ਪੂਰਨ);
ਸਥਿਰ ਬਣਤਰ dns_query *parse_dns_qsection(ਅਚਲ u_char *, ਪੂਰਨ,
    ਅਚਲ u_char **, ਪੂਰਨ);
ਸਥਿਰ ਬਣਤਰ dns_rr *parse_dns_rrsection(ਅਚਲ u_char *, ਪੂਰਨ, ਅਚਲ u_char **,
    ਪੂਰਨ);

ਸਥਿਰ ਖਾਲੀ free_dns_query(ਬਣਤਰ dns_query *);
ਸਥਿਰ ਖਾਲੀ free_dns_rr(ਬਣਤਰ dns_rr *);
ਸਥਿਰ ਖਾਲੀ free_dns_response(ਬਣਤਰ dns_response *);

ਸਥਿਰ ਪੂਰਨ ਗਿਣਤੀ_dns_rr(ਬਣਤਰ dns_rr *, u_int16_t, u_int16_t);

ਪੂਰਨ
getrrsetbyname(ਅਚਲ ਅੱਖਰ *hostname, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ rdclass,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ rdtype, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ flags,
    ਬਣਤਰ rrsetinfo **res)
{
	ਬਣਤਰ __res_state *_resp = THREAD_ਨਿੱਜੀ(_res, _res, &_res);
	ਪੂਰਨ ਨਤੀਜਾ;
	ਬਣਤਰ rrsetinfo *rrset = ਨਿਰਾ;
	ਬਣਤਰ dns_response *response = ਨਿਰਾ;
	ਬਣਤਰ dns_rr *rr;
	ਬਣਤਰ rdatainfo *rdata;
	ਪੂਰਨ ਲੰਮਾਈ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ ਸੂਚਕਾਂਕ_ans, ਸੂਚਕਾਂਕ_sig;
	u_char answer[ANSWER_ਬਫਰ_ਮਾਪ];

	/* check for invalid class and type */
	ਜੇ (rdclass > 0xffff || rdtype > 0xffff) {
		ਨਤੀਜਾ = ERRSET_INVAL;
		ਜਾਓ fail;
	}

	/* don't allow queries of class or type ANY */
	ਜੇ (rdclass == 0xff || rdtype == 0xff) {
		ਨਤੀਜਾ = ERRSET_INVAL;
		ਜਾਓ fail;
	}

	/* don't allow flags yet, unimplemented */
	ਜੇ (flags) {
		ਨਤੀਜਾ = ERRSET_INVAL;
		ਜਾਓ fail;
	}

	/* initialize resolver */
	ਜੇ ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		ਨਤੀਜਾ = ERRSET_FAIL;
		ਜਾਓ fail;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG
	_resp->options |= RES_DEBUG;
#ਜੇ_ਅੰਤ /* DEBUG */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ RES_USE_DNSSEC
	/* turn on DNSSEC if EDNS0 is configured */
	ਜੇ (_resp->options & RES_USE_EDNS0)
		_resp->options |= RES_USE_DNSSEC;
#ਜੇ_ਅੰਤ /* RES_USE_DNSEC */

	/* make query */
	ਲੰਮਾਈ = res_query(hostname, (ਨਿਸ਼ਾਨੀਵਾਲਾ ਪੂਰਨ) rdclass, (ਨਿਸ਼ਾਨੀਵਾਲਾ ਪੂਰਨ) rdtype,
	    answer, ਆਕਾਰ(answer));
	ਜੇ (ਲੰਮਾਈ < 0) {
		ਚੋਣ(h_errno) {
		ਹਾਲਤ HOST_NOT_FOUND:
			ਨਤੀਜਾ = ERRSET_NONAME;
			ਜਾਓ fail;
		ਹਾਲਤ NO_DATA:
			ਨਤੀਜਾ = ERRSET_NODATA;
			ਜਾਓ fail;
		ਮੂਲ:
			ਨਤੀਜਾ = ERRSET_FAIL;
			ਜਾਓ fail;
		}
	}

	/* parse result */
	response = parse_dns_response(answer, ਲੰਮਾਈ);
	ਜੇ (response == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_FAIL;
		ਜਾਓ fail;
	}

	ਜੇ (response->ਸਿਰਲੇਖ_3.qdcount != 1) {
		ਨਤੀਜਾ = ERRSET_FAIL;
		ਜਾਓ fail;
	}

	/* initialize rrset */
	rrset = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(ਬਣਤਰ rrsetinfo));
	ਜੇ (rrset == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}
	rrset->rri_rdclass = response->query->class;
	rrset->rri_rdtype = response->query->type;
	rrset->rri_ttl = response->answer->ttl;
	rrset->rri_nrdatas = response->ਸਿਰਲੇਖ_3.ancount;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਿਰਲੇਖ_AD
	/* check for authenticated data */
	ਜੇ (response->ਸਿਰਲੇਖ_3.ad == 1)
		rrset->rri_flags |= RRSET_VALIDATED;
#ਜੇ_ਅੰਤ

	/* copy name from answer section */
	rrset->rri_name = strdup(response->answer->name);
	ਜੇ (rrset->rri_name == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}

	/* count answers */
	rrset->rri_nrdatas = ਗਿਣਤੀ_dns_rr(response->answer, rrset->rri_rdclass,
	    rrset->rri_rdtype);
	rrset->rri_nsigs = ਗਿਣਤੀ_dns_rr(response->answer, rrset->rri_rdclass,
	    T_RRSIG);

	/* allocate memory for answers */
	rrset->rri_rdatas = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(rrset->rri_nrdatas,
	    ਆਕਾਰ(ਬਣਤਰ rdatainfo));
	ਜੇ (rrset->rri_rdatas == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}

	/* allocate memory for signatures */
	ਜੇ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(rrset->rri_nsigs, ਆਕਾਰ(ਬਣਤਰ rdatainfo));
		ਜੇ (rrset->rri_sigs == ਨਿਰਾ) {
			ਨਤੀਜਾ = ERRSET_NOMEMORY;
			ਜਾਓ fail;
		}
	}

	/* copy answers & signatures */
	ਲਈ (rr = response->answer, ਸੂਚਕਾਂਕ_ans = 0, ਸੂਚਕਾਂਕ_sig = 0;
	    rr; rr = rr->ਅਗਲਾ) {

		rdata = ਨਿਰਾ;

		ਜੇ (rr->class == rrset->rri_rdclass &&
		    rr->type  == rrset->rri_rdtype)
			rdata = &rrset->rri_rdatas[ਸੂਚਕਾਂਕ_ans++];

		ਜੇ (rr->class == rrset->rri_rdclass &&
		    rr->type  == T_RRSIG)
			rdata = &rrset->rri_sigs[ਸੂਚਕਾਂਕ_sig++];

		ਜੇ (rdata) {
			rdata->rdi_ਲੰਮਾਈ = rr->ਮਾਪ;
			ਜੇ (rr->ਮਾਪ != 0) {
				rdata->rdi_ਅੰਕੜੇ   = ਸਮ੍ਰਿਤੀ_ਦਿਓ(rr->ਮਾਪ);
				ਜੇ (rdata->rdi_ਅੰਕੜੇ == ਨਿਰਾ) {
					ਨਤੀਜਾ = ERRSET_NOMEMORY;
					ਜਾਓ fail;
				}
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(rdata->rdi_ਅੰਕੜੇ, rr->rdata, rr->ਮਾਪ);
			}
		}
	}
	free_dns_response(response);

	*res = rrset;
	ਵਾਪਸ (ERRSET_SUCCESS);

fail:
	ਜੇ (rrset != ਨਿਰਾ)
		freerrset(rrset);
	ਜੇ (response != ਨਿਰਾ)
		free_dns_response(response);
	ਵਾਪਸ (ਨਤੀਜਾ);
}

ਖਾਲੀ
freerrset(ਬਣਤਰ rrsetinfo *rrset)
{
	u_int16_t i;

	ਜੇ (rrset == ਨਿਰਾ)
		ਵਾਪਸ;

	ਜੇ (rrset->rri_rdatas) {
		ਲਈ (i = 0; i < rrset->rri_nrdatas; i++) {
			ਜੇ (rrset->rri_rdatas[i].rdi_ਅੰਕੜੇ == ਨਿਰਾ)
				ਰੋਕੋ;
			ਮੁਕਤ(rrset->rri_rdatas[i].rdi_ਅੰਕੜੇ);
		}
		ਮੁਕਤ(rrset->rri_rdatas);
	}

	ਜੇ (rrset->rri_sigs) {
		ਲਈ (i = 0; i < rrset->rri_nsigs; i++) {
			ਜੇ (rrset->rri_sigs[i].rdi_ਅੰਕੜੇ == ਨਿਰਾ)
				ਰੋਕੋ;
			ਮੁਕਤ(rrset->rri_sigs[i].rdi_ਅੰਕੜੇ);
		}
		ਮੁਕਤ(rrset->rri_sigs);
	}

	ਜੇ (rrset->rri_name)
		ਮੁਕਤ(rrset->rri_name);
	ਮੁਕਤ(rrset);
}

/*
 * DNS response parsing routines
 */
ਸਥਿਰ ਬਣਤਰ dns_response *
parse_dns_response(ਅਚਲ u_char *answer, ਪੂਰਨ ਮਾਪ)
{
	ਬਣਤਰ dns_response *resp;
	ਅਚਲ u_char *cp;

	ਜੇ (ਮਾਪ < HFIXEDSZ)
		ਵਾਪਸ (ਨਿਰਾ);

	/* allocate memory for the response */
	resp = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*resp));
	ਜੇ (resp == ਨਿਰਾ)
		ਵਾਪਸ (ਨਿਰਾ);

	/* initialize current pointer */
	cp = answer;

	/* copy header */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&resp->ਸਿਰਲੇਖ_3, cp, HFIXEDSZ);
	cp += HFIXEDSZ;

	/* fix header byte order */
	resp->ਸਿਰਲੇਖ_3.qdcount = ntohs(resp->ਸਿਰਲੇਖ_3.qdcount);
	resp->ਸਿਰਲੇਖ_3.ancount = ntohs(resp->ਸਿਰਲੇਖ_3.ancount);
	resp->ਸਿਰਲੇਖ_3.nscount = ntohs(resp->ਸਿਰਲੇਖ_3.nscount);
	resp->ਸਿਰਲੇਖ_3.arcount = ntohs(resp->ਸਿਰਲੇਖ_3.arcount);

	/* there must be at least one query */
	ਜੇ (resp->ਸਿਰਲੇਖ_3.qdcount < 1) {
		free_dns_response(resp);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* parse query section */
	resp->query = parse_dns_qsection(answer, ਮਾਪ, &cp,
	    resp->ਸਿਰਲੇਖ_3.qdcount);
	ਜੇ (resp->ਸਿਰਲੇਖ_3.qdcount && resp->query == ਨਿਰਾ) {
		free_dns_response(resp);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* parse answer section */
	resp->answer = parse_dns_rrsection(answer, ਮਾਪ, &cp,
	    resp->ਸਿਰਲੇਖ_3.ancount);
	ਜੇ (resp->ਸਿਰਲੇਖ_3.ancount && resp->answer == ਨਿਰਾ) {
		free_dns_response(resp);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* parse authority section */
	resp->authority = parse_dns_rrsection(answer, ਮਾਪ, &cp,
	    resp->ਸਿਰਲੇਖ_3.nscount);
	ਜੇ (resp->ਸਿਰਲੇਖ_3.nscount && resp->authority == ਨਿਰਾ) {
		free_dns_response(resp);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* parse additional section */
	resp->additional = parse_dns_rrsection(answer, ਮਾਪ, &cp,
	    resp->ਸਿਰਲੇਖ_3.arcount);
	ਜੇ (resp->ਸਿਰਲੇਖ_3.arcount && resp->additional == ਨਿਰਾ) {
		free_dns_response(resp);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	ਵਾਪਸ (resp);
}

ਸਥਿਰ ਬਣਤਰ dns_query *
parse_dns_qsection(ਅਚਲ u_char *answer, ਪੂਰਨ ਮਾਪ, ਅਚਲ u_char **cp, ਪੂਰਨ ਗਿਣਤੀ_2)
{
	ਬਣਤਰ dns_query *ਸਿਰ, *curr, *prev;
	ਪੂਰਨ i, ਲੰਮਾਈ;
	ਅੱਖਰ name[MAXDNAME];

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NEED(need) \
	ਕਰੋ { \
		ਜੇ (*cp + need > answer + ਮਾਪ) \
			ਜਾਓ fail; \
	} ਜਦੋਂ (0)

	ਲਈ (i = 1, ਸਿਰ = ਨਿਰਾ, prev = ਨਿਰਾ; i <= ਗਿਣਤੀ_2; i++, prev = curr) {
		ਜੇ (*cp >= answer + ਮਾਪ) {
 fail:
			free_dns_query(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		/* allocate and initialize struct */
		curr = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(ਬਣਤਰ dns_query));
		ਜੇ (curr == ਨਿਰਾ)
			ਜਾਓ fail;
		ਜੇ (ਸਿਰ == ਨਿਰਾ)
			ਸਿਰ = curr;
		ਜੇ (prev != ਨਿਰਾ)
			prev->ਅਗਲਾ = curr;

		/* name */
		ਲੰਮਾਈ = dn_expand(answer, answer + ਮਾਪ, *cp, name,
		    ਆਕਾਰ(name));
		ਜੇ (ਲੰਮਾਈ < 0) {
			free_dns_query(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		curr->name = strdup(name);
		ਜੇ (curr->name == ਨਿਰਾ) {
			free_dns_query(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		NEED(ਲੰਮਾਈ);
		*cp += ਲੰਮਾਈ;

		/* type */
		NEED(INT16SZ);
		curr->type = _getshort(*cp);
		*cp += INT16SZ;

		/* class */
		NEED(INT16SZ);
		curr->class = _getshort(*cp);
		*cp += INT16SZ;
	}
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ NEED

	ਵਾਪਸ (ਸਿਰ);
}

ਸਥਿਰ ਬਣਤਰ dns_rr *
parse_dns_rrsection(ਅਚਲ u_char *answer, ਪੂਰਨ ਮਾਪ, ਅਚਲ u_char **cp,
    ਪੂਰਨ ਗਿਣਤੀ_2)
{
	ਬਣਤਰ dns_rr *ਸਿਰ, *curr, *prev;
	ਪੂਰਨ i, ਲੰਮਾਈ;
	ਅੱਖਰ name[MAXDNAME];

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NEED(need) \
	ਕਰੋ { \
		ਜੇ (*cp + need > answer + ਮਾਪ) \
			ਜਾਓ fail; \
	} ਜਦੋਂ (0)

	ਲਈ (i = 1, ਸਿਰ = ਨਿਰਾ, prev = ਨਿਰਾ; i <= ਗਿਣਤੀ_2; i++, prev = curr) {
		ਜੇ (*cp >= answer + ਮਾਪ) {
 fail:
			free_dns_rr(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}

		/* allocate and initialize struct */
		curr = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(ਬਣਤਰ dns_rr));
		ਜੇ (curr == ਨਿਰਾ)
			ਜਾਓ fail;
		ਜੇ (ਸਿਰ == ਨਿਰਾ)
			ਸਿਰ = curr;
		ਜੇ (prev != ਨਿਰਾ)
			prev->ਅਗਲਾ = curr;

		/* name */
		ਲੰਮਾਈ = dn_expand(answer, answer + ਮਾਪ, *cp, name,
		    ਆਕਾਰ(name));
		ਜੇ (ਲੰਮਾਈ < 0) {
			free_dns_rr(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		curr->name = strdup(name);
		ਜੇ (curr->name == ਨਿਰਾ) {
			free_dns_rr(ਸਿਰ);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		NEED(ਲੰਮਾਈ);
		*cp += ਲੰਮਾਈ;

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
		curr->ਮਾਪ = _getshort(*cp);
		*cp += INT16SZ;

		/* rdata itself */
		NEED(curr->ਮਾਪ);
		ਜੇ (curr->ਮਾਪ != 0) {
			ਜੇ ((curr->rdata = ਸਮ੍ਰਿਤੀ_ਦਿਓ(curr->ਮਾਪ)) == ਨਿਰਾ) {
				free_dns_rr(ਸਿਰ);
				ਵਾਪਸ (ਨਿਰਾ);
			}
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(curr->rdata, *cp, curr->ਮਾਪ);
		}
		*cp += curr->ਮਾਪ;
	}
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ NEED

	ਵਾਪਸ (ਸਿਰ);
}

ਸਥਿਰ ਖਾਲੀ
free_dns_query(ਬਣਤਰ dns_query *p)
{
	ਬਣਤਰ dns_query *ਅਗਲਾ;

	ਜਦੋਂ (p != ਨਿਰਾ) {
		ਅਗਲਾ = p->ਅਗਲਾ;
		ਮੁਕਤ(p->name);
		ਮੁਕਤ(p);
		p = ਅਗਲਾ;
	}
}

ਸਥਿਰ ਖਾਲੀ
free_dns_rr(ਬਣਤਰ dns_rr *p)
{
	ਬਣਤਰ dns_rr *ਅਗਲਾ;

	ਜਦੋਂ (p != ਨਿਰਾ) {
		ਅਗਲਾ = p->ਅਗਲਾ;
		ਮੁਕਤ(p->name);
		ਮੁਕਤ(p->rdata);
		ਮੁਕਤ(p);
		p = ਅਗਲਾ;
	}
}

ਸਥਿਰ ਖਾਲੀ
free_dns_response(ਬਣਤਰ dns_response *p)
{
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ;

	free_dns_query(p->query);
	free_dns_rr(p->answer);
	free_dns_rr(p->authority);
	free_dns_rr(p->additional);
	ਮੁਕਤ(p);
}

ਸਥਿਰ ਪੂਰਨ
ਗਿਣਤੀ_dns_rr(ਬਣਤਰ dns_rr *p, u_int16_t class, u_int16_t type)
{
	ਪੂਰਨ n = 0;

	ਜਦੋਂ(p) {
		ਜੇ (p->class == class && p->type == type)
			n++;
		p = p->ਅਗਲਾ;
	}

	ਵਾਪਸ (n);
}

#ਜੇ_ਅੰਤ /*  !defined (HAVE_GETRRSETBYNAME) && !defined (HAVE_LDNS) */
