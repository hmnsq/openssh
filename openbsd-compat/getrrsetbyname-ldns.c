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

#जर !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <ldns/ldns.h>

#अन्तर्भाव "getrrsetbyname.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "xmalloc.h"

#define दो_स्मृति(x)	(xmalloc(x))
#define सुस्मृति(x, y)	(xcalloc((x),(y)))

पूर्णांक
getrrsetbyname(स्थिरांक अक्षर *hostname, अचिन्हित पूर्णांक rdclass,
	       अचिन्हित पूर्णांक rdtype, अचिन्हित पूर्णांक flags,
	       संरचना rrsetinfo **res)
{
	पूर्णांक result;
	अचिन्हित पूर्णांक i, j, index_ans, index_sig;
	संरचना rrsetinfo *rrset = रिक्त;
	संरचना rdatainfo *rdata;
	माप_प्रकार len;
	ldns_resolver *ldns_res = रिक्त;
	ldns_rdf *domain = रिक्त;
	ldns_pkt *pkt = रिक्त;
	ldns_rr_list *rrsigs = रिक्त, *rrdata = रिक्त;
	ldns_status err;
	ldns_rr *rr;

	/* check for invalid class and type */
	जर (rdclass > 0xffff || rdtype > 0xffff) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* don't allow queries of class or type ANY */
	जर (rdclass == 0xff || rdtype == 0xff) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* don't allow flags yet, unimplemented */
	जर (flags) {
		result = ERRSET_INVAL;
		जा fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	जर ((err = ldns_resolver_new_frm_file(&ldns_res, रिक्त)) != \
	    LDNS_STATUS_OK) {
		result = ERRSET_FAIL;
		जा fail;
	}

#ifdef LDNS_DEBUG
	ldns_resolver_set_debug(ldns_res, true);
#endif /* LDNS_DEBUG */

	ldns_resolver_set_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	जर (!pkt || ldns_pkt_ancount(pkt) < 1) {
		result = ERRSET_FAIL;
		जा fail;
	}

	/* initialize rrset */
	rrset = सुस्मृति(1, आकार(संरचना rrsetinfo));
	जर (rrset == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_मोजणी(rrdata);
	जर (!rrset->rri_nrdatas) {
		result = ERRSET_NODATA;
		जा fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_size(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	जर ((rrset->rri_name = दो_स्मृति(len)) == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}
	स_नकल(rrset->rri_name,
	    ldns_rdf_data(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	जर (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} अन्यथा { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_किल्ल्या = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_मोजणी(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		जर ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_किल्ल्या)) == LDNS_STATUS_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} अन्यथा {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_किल्ल्या);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = सुस्मृति(rrset->rri_nrdatas,
	   आकार(संरचना rdatainfo));

	जर (rrset->rri_rdatas == रिक्त) {
		result = ERRSET_NOMEMORY;
		जा fail;
	}

	/* allocate memory for signatures */
	जर (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = सुस्मृति(rrset->rri_nsigs,
		    आकार(संरचना rdatainfo));

		जर (rrset->rri_sigs == रिक्त) {
			result = ERRSET_NOMEMORY;
			जा fail;
		}
	}

	/* copy answers & signatures */
	साठी (i=0, index_ans=0, index_sig=0; i< pkt->_header->_ancount; i++) {
		rdata = रिक्त;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		जर (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[index_ans++];
		}

		जर (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[index_sig++];
		}

		जर (rdata) {
			माप_प्रकार rdata_offset = 0;

			rdata->rdi_length = 0;
			साठी (j=0; j< rr->rd_मोजणी; j++) {
				rdata->rdi_length +=
				    ldns_rdf_size(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_data = दो_स्मृति(rdata->rdi_length);
			जर (rdata->rdi_data == रिक्त) {
				result = ERRSET_NOMEMORY;
				जा fail;
			}

			/* Re-create the raw DNS RDATA */
			साठी (j=0; j< rr->rd_मोजणी; j++) {
				len = ldns_rdf_size(ldns_rr_rdf(rr, j));
				स_नकल(rdata->rdi_data + rdata_offset,
				       ldns_rdf_data(ldns_rr_rdf(rr, j)), len);
				rdata_offset += len;
			}
		}
	}

	*res = rrset;
	rrset = रिक्त; /* transferred */
	result = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	परत result;
}


शून्य
freerrset(संरचना rrsetinfo *rrset)
{
	u_int16_t i;

	जर (rrset == रिक्त)
		परत;

	जर (rrset->rri_rdatas) {
		साठी (i = 0; i < rrset->rri_nrdatas; i++) {
			जर (rrset->rri_rdatas[i].rdi_data == रिक्त)
				थांबा;
			मुक्त(rrset->rri_rdatas[i].rdi_data);
		}
		मुक्त(rrset->rri_rdatas);
	}

	जर (rrset->rri_sigs) {
		साठी (i = 0; i < rrset->rri_nsigs; i++) {
			जर (rrset->rri_sigs[i].rdi_data == रिक्त)
				थांबा;
			मुक्त(rrset->rri_sigs[i].rdi_data);
		}
		मुक्त(rrset->rri_sigs);
	}

	जर (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}


#endif /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
