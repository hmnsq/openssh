/* $OpenBSD: getrrsetbyname.c,v 1.10 2005/03/30 02:58:28 tedu Exp $ */

/*
 * Copyright (c) 2007 Simon Vallet / Genoscope <svallet@genoscope.cns.fr>
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ldns/ldns.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "getrrsetbyname.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸਮ੍ਰਿਤੀ_ਦਿਓ(x)	(xmalloc(x))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(x, y)	(xcalloc((x),(y)))

ਪੂਰਨ
getrrsetbyname(ਅਚਲ ਅੱਖਰ *hostname, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ rdclass,
	       ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ rdtype, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ flags,
	       ਬਣਤਰ rrsetinfo **res)
{
	ਪੂਰਨ ਨਤੀਜਾ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i, j, ਸੂਚਕਾਂਕ_ans, ਸੂਚਕਾਂਕ_sig;
	ਬਣਤਰ rrsetinfo *rrset = ਨਿਰਾ;
	ਬਣਤਰ rdatainfo *rdata;
	ਮਾਪ_t len;
	ldns_resolver *ldns_res = ਨਿਰਾ;
	ldns_rdf *domain = ਨਿਰਾ;
	ldns_pkt *pkt = ਨਿਰਾ;
	ldns_rr_list *rrsigs = ਨਿਰਾ, *rrdata = ਨਿਰਾ;
	ldns_ਸਥਿਤੀ err;
	ldns_rr *rr;

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

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	ਜੇ ((err = ldns_resolver_new_frm_file(&ldns_res, ਨਿਰਾ)) != \
	    LDNS_ਸਥਿਤੀ_OK) {
		ਨਤੀਜਾ = ERRSET_FAIL;
		ਜਾਓ fail;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LDNS_DEBUG
	ldns_resolver_ਸੈੱਟ_debug(ldns_res, true);
#ਜੇ_ਅੰਤ /* LDNS_DEBUG */

	ldns_resolver_ਸੈੱਟ_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	ਜੇ (!pkt || ldns_pkt_ancount(pkt) < 1) {
		ਨਤੀਜਾ = ERRSET_FAIL;
		ਜਾਓ fail;
	}

	/* initialize rrset */
	rrset = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(ਬਣਤਰ rrsetinfo));
	ਜੇ (rrset == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_ਗਿਣਤੀ(rrdata);
	ਜੇ (!rrset->rri_nrdatas) {
		ਨਤੀਜਾ = ERRSET_NODATA;
		ਜਾਓ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_ਮਾਪ(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	ਜੇ ((rrset->rri_name = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(rrset->rri_name,
	    ldns_rdf_ਅੰਕੜੇ(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	ਜੇ (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} ਨਹੀਂਤਾਂ { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_ਕੁੰਜੀਆਂ = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_ਗਿਣਤੀ(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		ਜੇ ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_ਕੁੰਜੀਆਂ)) == LDNS_ਸਥਿਤੀ_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} ਨਹੀਂਤਾਂ {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_ਕੁੰਜੀਆਂ);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(rrset->rri_nrdatas,
	   ਆਕਾਰ(ਬਣਤਰ rdatainfo));

	ਜੇ (rrset->rri_rdatas == ਨਿਰਾ) {
		ਨਤੀਜਾ = ERRSET_NOMEMORY;
		ਜਾਓ fail;
	}

	/* allocate memory for signatures */
	ਜੇ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(rrset->rri_nsigs,
		    ਆਕਾਰ(ਬਣਤਰ rdatainfo));

		ਜੇ (rrset->rri_sigs == ਨਿਰਾ) {
			ਨਤੀਜਾ = ERRSET_NOMEMORY;
			ਜਾਓ fail;
		}
	}

	/* copy answers & signatures */
	ਲਈ (i=0, ਸੂਚਕਾਂਕ_ans=0, ਸੂਚਕਾਂਕ_sig=0; i< pkt->ਸਿਰਲੇਖ->_ancount; i++) {
		rdata = ਨਿਰਾ;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		ਜੇ (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[ਸੂਚਕਾਂਕ_ans++];
		}

		ਜੇ (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[ਸੂਚਕਾਂਕ_sig++];
		}

		ਜੇ (rdata) {
			ਮਾਪ_t rdata_ਵਿੱਥ = 0;

			rdata->rdi_ਲੰਮਾਈ = 0;
			ਲਈ (j=0; j< rr->rd_ਗਿਣਤੀ; j++) {
				rdata->rdi_ਲੰਮਾਈ +=
				    ldns_rdf_ਮਾਪ(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_ਅੰਕੜੇ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(rdata->rdi_ਲੰਮਾਈ);
			ਜੇ (rdata->rdi_ਅੰਕੜੇ == ਨਿਰਾ) {
				ਨਤੀਜਾ = ERRSET_NOMEMORY;
				ਜਾਓ fail;
			}

			/* Re-create the raw DNS RDATA */
			ਲਈ (j=0; j< rr->rd_ਗਿਣਤੀ; j++) {
				len = ldns_rdf_ਮਾਪ(ldns_rr_rdf(rr, j));
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(rdata->rdi_ਅੰਕੜੇ + rdata_ਵਿੱਥ,
				       ldns_rdf_ਅੰਕੜੇ(ldns_rr_rdf(rr, j)), len);
				rdata_ਵਿੱਥ += len;
			}
		}
	}

	*res = rrset;
	rrset = ਨਿਰਾ; /* transferred */
	ਨਤੀਜਾ = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	ਵਾਪਸ ਨਤੀਜਾ;
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


#ਜੇ_ਅੰਤ /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
