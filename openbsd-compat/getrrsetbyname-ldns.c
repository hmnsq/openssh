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

#अन्तर्भाव "includes.h"

#यदि !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <ldns/ldns.h>

#अन्तर्भाव "getrrsetbyname.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "xmalloc.h"

#परिभाषय स्मृतिं_देहि(x)	(xmalloc(x))
#परिभाषय शून्यस्मृतिं_देहि(x, y)	(xcalloc((x),(y)))

पूर्णाङ्क
getrrsetbyname(ध्रुव वर्ण *hostname, अचिह्नित पूर्णाङ्क rdclass,
	       अचिह्नित पूर्णाङ्क rdtype, अचिह्नित पूर्णाङ्क flags,
	       संरचना rrsetinfo **res)
{
	पूर्णाङ्क परिणाम;
	अचिह्नित पूर्णाङ्क i, j, सूचकांक_ans, सूचकांक_sig;
	संरचना rrsetinfo *rrset = रिक्त;
	संरचना rdatainfo *rdata;
	आकार_t len;
	ldns_resolver *ldns_res = रिक्त;
	ldns_rdf *domain = रिक्त;
	ldns_pkt *pkt = रिक्त;
	ldns_rr_list *rrsigs = रिक्त, *rrdata = रिक्त;
	ldns_स्थितिः err;
	ldns_rr *rr;

	/* check for invalid class and type */
	यदि (rdclass > 0xffff || rdtype > 0xffff) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow queries of class or type ANY */
	यदि (rdclass == 0xff || rdtype == 0xff) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* don't allow flags yet, unimplemented */
	यदि (flags) {
		परिणाम = ERRSET_INVAL;
		गच्छ fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	यदि ((err = ldns_resolver_new_frm_file(&ldns_res, रिक्त)) != \
	    LDNS_स्थितिः_OK) {
		परिणाम = ERRSET_FAIL;
		गच्छ fail;
	}

#यदि_परिभाषितम् LDNS_DEBUG
	ldns_resolver_समुच्चयः_debug(ldns_res, true);
#यदि_अन्तः /* LDNS_DEBUG */

	ldns_resolver_समुच्चयः_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	यदि (!pkt || ldns_pkt_ancount(pkt) < 1) {
		परिणाम = ERRSET_FAIL;
		गच्छ fail;
	}

	/* initialize rrset */
	rrset = शून्यस्मृतिं_देहि(1, परिमाण(संरचना rrsetinfo));
	यदि (rrset == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_गणनम्(rrdata);
	यदि (!rrset->rri_nrdatas) {
		परिणाम = ERRSET_NODATA;
		गच्छ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_आकार(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	यदि ((rrset->rri_name = स्मृतिं_देहि(len)) == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}
	स्मृतिं_प्रतिलिख(rrset->rri_name,
	    ldns_rdf_दत्त(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	यदि (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} अन्यथा { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_कुञ्चिकाः = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_गणनम्(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		यदि ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_कुञ्चिकाः)) == LDNS_स्थितिः_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} अन्यथा {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_कुञ्चिकाः);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = शून्यस्मृतिं_देहि(rrset->rri_nrdatas,
	   परिमाण(संरचना rdatainfo));

	यदि (rrset->rri_rdatas == रिक्त) {
		परिणाम = ERRSET_NOMEMORY;
		गच्छ fail;
	}

	/* allocate memory for signatures */
	यदि (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = शून्यस्मृतिं_देहि(rrset->rri_nsigs,
		    परिमाण(संरचना rdatainfo));

		यदि (rrset->rri_sigs == रिक्त) {
			परिणाम = ERRSET_NOMEMORY;
			गच्छ fail;
		}
	}

	/* copy answers & signatures */
	प्रति (i=0, सूचकांक_ans=0, सूचकांक_sig=0; i< pkt->शीर्षकम्->_ancount; i++) {
		rdata = रिक्त;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		यदि (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[सूचकांक_ans++];
		}

		यदि (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[सूचकांक_sig++];
		}

		यदि (rdata) {
			आकार_t rdata_विस्थापनम् = 0;

			rdata->rdi_दीर्घता = 0;
			प्रति (j=0; j< rr->rd_गणनम्; j++) {
				rdata->rdi_दीर्घता +=
				    ldns_rdf_आकार(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_दत्त = स्मृतिं_देहि(rdata->rdi_दीर्घता);
			यदि (rdata->rdi_दत्त == रिक्त) {
				परिणाम = ERRSET_NOMEMORY;
				गच्छ fail;
			}

			/* Re-create the raw DNS RDATA */
			प्रति (j=0; j< rr->rd_गणनम्; j++) {
				len = ldns_rdf_आकार(ldns_rr_rdf(rr, j));
				स्मृतिं_प्रतिलिख(rdata->rdi_दत्त + rdata_विस्थापनम्,
				       ldns_rdf_दत्त(ldns_rr_rdf(rr, j)), len);
				rdata_विस्थापनम् += len;
			}
		}
	}

	*res = rrset;
	rrset = रिक्त; /* transferred */
	परिणाम = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	प्रत्यागम परिणाम;
}


शून्य
freerrset(संरचना rrsetinfo *rrset)
{
	u_int16_t i;

	यदि (rrset == रिक्त)
		प्रत्यागम;

	यदि (rrset->rri_rdatas) {
		प्रति (i = 0; i < rrset->rri_nrdatas; i++) {
			यदि (rrset->rri_rdatas[i].rdi_दत्त == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_rdatas[i].rdi_दत्त);
		}
		मुक्त(rrset->rri_rdatas);
	}

	यदि (rrset->rri_sigs) {
		प्रति (i = 0; i < rrset->rri_nsigs; i++) {
			यदि (rrset->rri_sigs[i].rdi_दत्त == रिक्त)
				भङ्ग;
			मुक्त(rrset->rri_sigs[i].rdi_दत्त);
		}
		मुक्त(rrset->rri_sigs);
	}

	यदि (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}


#यदि_अन्तः /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
