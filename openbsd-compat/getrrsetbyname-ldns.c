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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <ldns/ldns.h>

#అన్తర్భావ "getrrsetbyname.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "xmalloc.h"

#నిర్వచించు జ్ఞాపకం_ఇవ్వు(x)	(xmalloc(x))
#నిర్వచించు సున్నా_జ్ఞాపకం_ఇవ్వు(x, y)	(xcalloc((x),(y)))

పూర్ణాంకం
getrrsetbyname(స్థిరరాశి అక్షరం *hostname, గుర్తులేని పూర్ణాంకం rdclass,
	       గుర్తులేని పూర్ణాంకం rdtype, గుర్తులేని పూర్ణాంకం flags,
	       నిర్మాణం rrsetinfo **res)
{
	పూర్ణాంకం ఫలితం;
	గుర్తులేని పూర్ణాంకం i, j, సూచీ_ans, సూచీ_sig;
	నిర్మాణం rrsetinfo *rrset = ఖాళీ;
	నిర్మాణం rdatainfo *rdata;
	కొలత_t len;
	ldns_resolver *ldns_res = ఖాళీ;
	ldns_rdf *domain = ఖాళీ;
	ldns_pkt *pkt = ఖాళీ;
	ldns_rr_list *rrsigs = ఖాళీ, *rrdata = ఖాళీ;
	ldns_స్థితి err;
	ldns_rr *rr;

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

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	ఒకవేళ ((err = ldns_resolver_new_frm_file(&ldns_res, ఖాళీ)) != \
	    LDNS_స్థితి_OK) {
		ఫలితం = ERRSET_FAIL;
		వెళ్ళు fail;
	}

#నిర్వచితమైతే LDNS_DEBUG
	ldns_resolver_సమితి_debug(ldns_res, true);
#అయితే_ముగింపు /* LDNS_DEBUG */

	ldns_resolver_సమితి_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	ఒకవేళ (!pkt || ldns_pkt_ancount(pkt) < 1) {
		ఫలితం = ERRSET_FAIL;
		వెళ్ళు fail;
	}

	/* initialize rrset */
	rrset = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(నిర్మాణం rrsetinfo));
	ఒకవేళ (rrset == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_లెక్క(rrdata);
	ఒకవేళ (!rrset->rri_nrdatas) {
		ఫలితం = ERRSET_NODATA;
		వెళ్ళు fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_కొలత(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	ఒకవేళ ((rrset->rri_name = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}
	జ్ఞాపకం_నకలు(rrset->rri_name,
	    ldns_rdf_దత్తాంశం(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	ఒకవేళ (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} లేకపోతే { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_కీలకాలు = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_లెక్క(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		ఒకవేళ ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_కీలకాలు)) == LDNS_స్థితి_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} లేకపోతే {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_కీలకాలు);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = సున్నా_జ్ఞాపకం_ఇవ్వు(rrset->rri_nrdatas,
	   పరిమాణం(నిర్మాణం rdatainfo));

	ఒకవేళ (rrset->rri_rdatas == ఖాళీ) {
		ఫలితం = ERRSET_NOMEMORY;
		వెళ్ళు fail;
	}

	/* allocate memory for signatures */
	ఒకవేళ (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = సున్నా_జ్ఞాపకం_ఇవ్వు(rrset->rri_nsigs,
		    పరిమాణం(నిర్మాణం rdatainfo));

		ఒకవేళ (rrset->rri_sigs == ఖాళీ) {
			ఫలితం = ERRSET_NOMEMORY;
			వెళ్ళు fail;
		}
	}

	/* copy answers & signatures */
	కొరకు (i=0, సూచీ_ans=0, సూచీ_sig=0; i< pkt->శీర్షిక->_ancount; i++) {
		rdata = ఖాళీ;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		ఒకవేళ (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[సూచీ_ans++];
		}

		ఒకవేళ (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[సూచీ_sig++];
		}

		ఒకవేళ (rdata) {
			కొలత_t rdata_స్థానభ్రంశం = 0;

			rdata->rdi_నిడివి = 0;
			కొరకు (j=0; j< rr->rd_లెక్క; j++) {
				rdata->rdi_నిడివి +=
				    ldns_rdf_కొలత(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_దత్తాంశం = జ్ఞాపకం_ఇవ్వు(rdata->rdi_నిడివి);
			ఒకవేళ (rdata->rdi_దత్తాంశం == ఖాళీ) {
				ఫలితం = ERRSET_NOMEMORY;
				వెళ్ళు fail;
			}

			/* Re-create the raw DNS RDATA */
			కొరకు (j=0; j< rr->rd_లెక్క; j++) {
				len = ldns_rdf_కొలత(ldns_rr_rdf(rr, j));
				జ్ఞాపకం_నకలు(rdata->rdi_దత్తాంశం + rdata_స్థానభ్రంశం,
				       ldns_rdf_దత్తాంశం(ldns_rr_rdf(rr, j)), len);
				rdata_స్థానభ్రంశం += len;
			}
		}
	}

	*res = rrset;
	rrset = ఖాళీ; /* transferred */
	ఫలితం = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	తిరిగి ఫలితం;
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


#అయితే_ముగింపు /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
