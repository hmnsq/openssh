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

#شامل "includes.h"

#اگر !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#شامل <stdlib.h>
#شامل <string.h>

#شامل <ldns/ldns.h>

#شامل "getrrsetbyname.h"
#شامل "log.h"
#شامل "xmalloc.h"

#define malloc(x)	(xmalloc(x))
#define calloc(x, y)	(xcalloc((x),(y)))

صحیح
getrrsetbyname(ثابت نویسه *hostname, unsigned صحیح rdclass,
	       unsigned صحیح rdtype, unsigned صحیح flags,
	       ساختار rrsetinfo **res)
{
	صحیح result;
	unsigned صحیح i, j, index_ans, index_sig;
	ساختار rrsetinfo *rrset = پوچ;
	ساختار rdatainfo *rdata;
	size_t len;
	ldns_resolver *ldns_res = پوچ;
	ldns_rdf *domain = پوچ;
	ldns_pkt *pkt = پوچ;
	ldns_rr_list *rrsigs = پوچ, *rrdata = پوچ;
	ldns_status err;
	ldns_rr *rr;

	/* check for invalid class and type */
	اگر (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* don't allow queries of class or type ANY */
	اگر (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* don't allow flags yet, unimplemented */
	اگر (flags) {
		result = ERRSET_INVAL;
		برو fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	اگر ((err = ldns_resolver_new_frm_file(&ldns_res, پوچ)) != \
	    LDNS_STATUS_OK) {
		result = ERRSET_FAIL;
		برو fail;
	}

#ifdef LDNS_DEBUG
	ldns_resolver_set_debug(ldns_res, true);
#endif /* LDNS_DEBUG */

	ldns_resolver_set_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	اگر (!pkt || ldns_pkt_ancount(pkt) < 1) {
		result = ERRSET_FAIL;
		برو fail;
	}

	/* initialize rrset */
	rrset = calloc(1, اندازه(ساختار rrsetinfo));
	اگر (rrset == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_شمار(rrdata);
	اگر (!rrset->rri_nrdatas) {
		result = ERRSET_NODATA;
		برو fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_size(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	اگر ((rrset->rri_name = malloc(len)) == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}
	memcpy(rrset->rri_name,
	    ldns_rdf_data(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	اگر (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} وگرنه { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_کلیدها = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_شمار(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		اگر ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_کلیدها)) == LDNS_STATUS_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} وگرنه {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_کلیدها);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	   اندازه(ساختار rdatainfo));

	اگر (rrset->rri_rdatas == پوچ) {
		result = ERRSET_NOMEMORY;
		برو fail;
	}

	/* allocate memory for signatures */
	اگر (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs,
		    اندازه(ساختار rdatainfo));

		اگر (rrset->rri_sigs == پوچ) {
			result = ERRSET_NOMEMORY;
			برو fail;
		}
	}

	/* copy answers & signatures */
	برای (i=0, index_ans=0, index_sig=0; i< pkt->_header->_ancount; i++) {
		rdata = پوچ;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		اگر (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[index_ans++];
		}

		اگر (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[index_sig++];
		}

		اگر (rdata) {
			size_t rdata_offset = 0;

			rdata->rdi_length = 0;
			برای (j=0; j< rr->rd_شمار; j++) {
				rdata->rdi_length +=
				    ldns_rdf_size(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_data = malloc(rdata->rdi_length);
			اگر (rdata->rdi_data == پوچ) {
				result = ERRSET_NOMEMORY;
				برو fail;
			}

			/* Re-create the raw DNS RDATA */
			برای (j=0; j< rr->rd_شمار; j++) {
				len = ldns_rdf_size(ldns_rr_rdf(rr, j));
				memcpy(rdata->rdi_data + rdata_offset,
				       ldns_rdf_data(ldns_rr_rdf(rr, j)), len);
				rdata_offset += len;
			}
		}
	}

	*res = rrset;
	rrset = پوچ; /* transferred */
	result = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	بازگشت result;
}


تهی
freerrset(ساختار rrsetinfo *rrset)
{
	u_int16_t i;

	اگر (rrset == پوچ)
		بازگشت;

	اگر (rrset->rri_rdatas) {
		برای (i = 0; i < rrset->rri_nrdatas; i++) {
			اگر (rrset->rri_rdatas[i].rdi_data == پوچ)
				بشکن;
			آزاد(rrset->rri_rdatas[i].rdi_data);
		}
		آزاد(rrset->rri_rdatas);
	}

	اگر (rrset->rri_sigs) {
		برای (i = 0; i < rrset->rri_nsigs; i++) {
			اگر (rrset->rri_sigs[i].rdi_data == پوچ)
				بشکن;
			آزاد(rrset->rri_sigs[i].rdi_data);
		}
		آزاد(rrset->rri_sigs);
	}

	اگر (rrset->rri_name)
		آزاد(rrset->rri_name);
	آزاد(rrset);
}


#endif /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
