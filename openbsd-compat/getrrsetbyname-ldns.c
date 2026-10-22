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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <ldns/ldns.h>

#ଅନ୍ତର୍ଭାଵ "getrrsetbyname.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

#define malloc(x)	(xmalloc(x))
#define calloc(x, y)	(xcalloc((x),(y)))

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getrrsetbyname(ଅଚଳ ଅକ୍ଷର *hostname, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdclass,
	       unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା rdtype, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
	       ସଂରଚନା rrsetinfo **res)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j, index_ans, index_sig;
	ସଂରଚନା rrsetinfo *rrset = ଖାଲି;
	ସଂରଚନା rdatainfo *rdata;
	size_t len;
	ldns_resolver *ldns_res = ଖାଲି;
	ldns_rdf *domain = ଖାଲି;
	ldns_pkt *pkt = ଖାଲି;
	ldns_rr_list *rrsigs = ଖାଲି, *rrdata = ଖାଲି;
	ldns_status err;
	ldns_rr *rr;

	/* check for invalid class and type */
	ଯଦି (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* don't allow queries of class or type ANY */
	ଯଦି (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* don't allow flags yet, unimplemented */
	ଯଦି (flags) {
		result = ERRSET_INVAL;
		ଯାଅ fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	ଯଦି ((err = ldns_resolver_new_frm_file(&ldns_res, ଖାଲି)) != \
	    LDNS_STATUS_OK) {
		result = ERRSET_FAIL;
		ଯାଅ fail;
	}

#ifdef LDNS_DEBUG
	ldns_resolver_set_debug(ldns_res, true);
#endif /* LDNS_DEBUG */

	ldns_resolver_set_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	ଯଦି (!pkt || ldns_pkt_ancount(pkt) < 1) {
		result = ERRSET_FAIL;
		ଯାଅ fail;
	}

	/* initialize rrset */
	rrset = calloc(1, ଆକାର(ସଂରଚନା rrsetinfo));
	ଯଦି (rrset == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_ଗଣନା(rrdata);
	ଯଦି (!rrset->rri_nrdatas) {
		result = ERRSET_NODATA;
		ଯାଅ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_size(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	ଯଦି ((rrset->rri_name = malloc(len)) == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}
	memcpy(rrset->rri_name,
	    ldns_rdf_data(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	ଯଦି (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} ଅନ୍ୟଥା { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_ଚାବିଗୁଡ଼ିକ = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_ଗଣନା(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		ଯଦି ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_ଚାବିଗୁଡ଼ିକ)) == LDNS_STATUS_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} ଅନ୍ୟଥା {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_ଚାବିଗୁଡ଼ିକ);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = calloc(rrset->rri_nrdatas,
	   ଆକାର(ସଂରଚନା rdatainfo));

	ଯଦି (rrset->rri_rdatas == ଖାଲି) {
		result = ERRSET_NOMEMORY;
		ଯାଅ fail;
	}

	/* allocate memory for signatures */
	ଯଦି (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = calloc(rrset->rri_nsigs,
		    ଆକାର(ସଂରଚନା rdatainfo));

		ଯଦି (rrset->rri_sigs == ଖାଲି) {
			result = ERRSET_NOMEMORY;
			ଯାଅ fail;
		}
	}

	/* copy answers & signatures */
	ପାଇଁ (i=0, index_ans=0, index_sig=0; i< pkt->_header->_ancount; i++) {
		rdata = ଖାଲି;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		ଯଦି (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[index_ans++];
		}

		ଯଦି (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[index_sig++];
		}

		ଯଦି (rdata) {
			size_t rdata_offset = 0;

			rdata->rdi_length = 0;
			ପାଇଁ (j=0; j< rr->rd_ଗଣନା; j++) {
				rdata->rdi_length +=
				    ldns_rdf_size(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_data = malloc(rdata->rdi_length);
			ଯଦି (rdata->rdi_data == ଖାଲି) {
				result = ERRSET_NOMEMORY;
				ଯାଅ fail;
			}

			/* Re-create the raw DNS RDATA */
			ପାଇଁ (j=0; j< rr->rd_ଗଣନା; j++) {
				len = ldns_rdf_size(ldns_rr_rdf(rr, j));
				memcpy(rdata->rdi_data + rdata_offset,
				       ldns_rdf_data(ldns_rr_rdf(rr, j)), len);
				rdata_offset += len;
			}
		}
	}

	*res = rrset;
	rrset = ଖାଲି; /* transferred */
	result = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	ଫେରନ୍ତୁ result;
}


ଶୂନ୍ୟ
freerrset(ସଂରଚନା rrsetinfo *rrset)
{
	u_int16_t i;

	ଯଦି (rrset == ଖାଲି)
		ଫେରନ୍ତୁ;

	ଯଦି (rrset->rri_rdatas) {
		ପାଇଁ (i = 0; i < rrset->rri_nrdatas; i++) {
			ଯଦି (rrset->rri_rdatas[i].rdi_data == ଖାଲି)
				ଭାଙ୍ଗ;
			ମୁକ୍ତ(rrset->rri_rdatas[i].rdi_data);
		}
		ମୁକ୍ତ(rrset->rri_rdatas);
	}

	ଯଦି (rrset->rri_sigs) {
		ପାଇଁ (i = 0; i < rrset->rri_nsigs; i++) {
			ଯଦି (rrset->rri_sigs[i].rdi_data == ଖାଲି)
				ଭାଙ୍ଗ;
			ମୁକ୍ତ(rrset->rri_sigs[i].rdi_data);
		}
		ମୁକ୍ତ(rrset->rri_sigs);
	}

	ଯଦି (rrset->rri_name)
		ମୁକ୍ତ(rrset->rri_name);
	ମୁକ୍ତ(rrset);
}


#endif /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
