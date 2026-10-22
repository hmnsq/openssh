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

#অন্তর্ভাৱ "includes.h"

#যদি !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ <ldns/ldns.h>

#অন্তর্ভাৱ "getrrsetbyname.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "xmalloc.h"

#define malloc(x)	(xmalloc(x))
#define calloc(x, y)	(xcalloc((x),(y)))

পূর্ণাঙ্ক
getrrsetbyname(ধ্রুৱ ৱর্ণ *hostname, unsigned পূর্ণাঙ্ক rdclass,
	       unsigned পূর্ণাঙ্ক rdtype, unsigned পূর্ণাঙ্ক flags,
	       সংরচনা rrsetinfo **res)
{
	পূর্ণাঙ্ক result;
	unsigned পূর্ণাঙ্ক i, j, index_ans, index_sig;
	সংরচনা rrsetinfo *rrset = রিক্ত;
	সংরচনা rdatainfo *rdata;
	size_t len;
	ldns_resolver *ldns_res = রিক্ত;
	ldns_rdf *domain = রিক্ত;
	ldns_pkt *pkt = রিক্ত;
	ldns_rr_list *rrsigs = রিক্ত, *rrdata = রিক্ত;
	ldns_status err;
	ldns_rr *rr;

	/* check for invalid class and type */
	যদি (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* don't allow queries of class or type ANY */
	যদি (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* don't allow flags yet, unimplemented */
	যদি (flags) {
		result = ERRSET_INVAL;
		গচ্ছ fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	যদি ((err = ldns_resolver_new_frm_file(&ldns_res, রিক্ত)) != \
	    LDNS_STATUS_OK) {
		result = ERRSET_FAIL;
		গচ্ছ fail;
	}

#ifdef LDNS_DEBUG
	ldns_resolver_set_debug(ldns_res, true);
#endif /* LDNS_DEBUG */

	ldns_resolver_set_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	যদি (!pkt || ldns_pkt_ancount(pkt) < 1) {
		result = ERRSET_FAIL;
		গচ্ছ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, পরিমাণ(সংরচনা rrsetinfo));
	যদি (rrset == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_গুনতি(rrdata);
	যদি (!rrset->rri_nrdatas) {
		result = ERRSET_NODATA;
		গচ্ছ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_size(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	যদি ((rrset->rri_name = malloc(len)) == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
	}
	memcpy(rrset->rri_name,
	    ldns_rdf_data(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	যদি (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} অন্যথা { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_চাবিগুলি = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_গুনতি(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		যদি ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_চাবিগুলি)) == LDNS_STATUS_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} অন্যথা {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_চাবিগুলি);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	   পরিমাণ(সংরচনা rdatainfo));

	যদি (rrset->rri_rdatas == রিক্ত) {
		result = ERRSET_NOMEMORY;
		গচ্ছ fail;
	}

	/* allocate memory for signatures */
	যদি (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs,
		    পরিমাণ(সংরচনা rdatainfo));

		যদি (rrset->rri_sigs == রিক্ত) {
			result = ERRSET_NOMEMORY;
			গচ্ছ fail;
		}
	}

	/* copy answers & signatures */
	বাবে (i=0, index_ans=0, index_sig=0; i< pkt->_header->_ancount; i++) {
		rdata = রিক্ত;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		যদি (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[index_ans++];
		}

		যদি (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[index_sig++];
		}

		যদি (rdata) {
			size_t rdata_offset = 0;

			rdata->rdi_length = 0;
			বাবে (j=0; j< rr->rd_গুনতি; j++) {
				rdata->rdi_length +=
				    ldns_rdf_size(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_data = malloc(rdata->rdi_length);
			যদি (rdata->rdi_data == রিক্ত) {
				result = ERRSET_NOMEMORY;
				গচ্ছ fail;
			}

			/* Re-create the raw DNS RDATA */
			বাবে (j=0; j< rr->rd_গুনতি; j++) {
				len = ldns_rdf_size(ldns_rr_rdf(rr, j));
				memcpy(rdata->rdi_data + rdata_offset,
				       ldns_rdf_data(ldns_rr_rdf(rr, j)), len);
				rdata_offset += len;
			}
		}
	}

	*res = rrset;
	rrset = রিক্ত; /* transferred */
	result = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	ঘূৰাই result;
}


শূন্য
freerrset(সংরচনা rrsetinfo *rrset)
{
	u_int16_t i;

	যদি (rrset == রিক্ত)
		ঘূৰাই;

	যদি (rrset->rri_rdatas) {
		বাবে (i = 0; i < rrset->rri_nrdatas; i++) {
			যদি (rrset->rri_rdatas[i].rdi_data == রিক্ত)
				ভঙ্গ;
			মুক্ত(rrset->rri_rdatas[i].rdi_data);
		}
		মুক্ত(rrset->rri_rdatas);
	}

	যদি (rrset->rri_sigs) {
		বাবে (i = 0; i < rrset->rri_nsigs; i++) {
			যদি (rrset->rri_sigs[i].rdi_data == রিক্ত)
				ভঙ্গ;
			মুক্ত(rrset->rri_sigs[i].rdi_data);
		}
		মুক্ত(rrset->rri_sigs);
	}

	যদি (rrset->rri_name)
		মুক্ত(rrset->rri_name);
	মুক্ত(rrset);
}


#endif /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
