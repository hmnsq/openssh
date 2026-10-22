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

#समावेश "includes.h"

#अगर !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <ldns/ldns.h>

#समावेश "getrrsetbyname.h"
#समावेश "log.h"
#समावेश "xmalloc.h"

#घोषणा दो_स्मृति(x)	(xmalloc(x))
#घोषणा सुस्मृति(x, y)	(xcalloc((x),(y)))

पूर्णांक
getrrsetbyname(स्थिर अक्षर *hostname, अचिन्हित पूर्णांक rdclass,
	       अचिन्हित पूर्णांक rdtype, अचिन्हित पूर्णांक flags,
	       काष्ठा rrsetinfo **res)
{
	पूर्णांक परिणाम;
	अचिन्हित पूर्णांक i, j, सूचकांक_ans, सूचकांक_sig;
	काष्ठा rrsetinfo *rrset = शून्य;
	काष्ठा rdatainfo *rdata;
	माप_प्रकार len;
	ldns_resolver *ldns_res = शून्य;
	ldns_rdf *domain = शून्य;
	ldns_pkt *pkt = शून्य;
	ldns_rr_list *rrsigs = शून्य, *rrdata = शून्य;
	ldns_status err;
	ldns_rr *rr;

	/* check for invalid class and type */
	अगर (rdclass > 0xffff || rdtype > 0xffff) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* don't allow queries of class or type ANY */
	अगर (rdclass == 0xff || rdtype == 0xff) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* don't allow flags yet, unimplemented */
	अगर (flags) {
		परिणाम = ERRSET_INVAL;
		जाओ fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	अगर ((err = ldns_resolver_new_frm_file(&ldns_res, शून्य)) != \
	    LDNS_STATUS_OK) {
		परिणाम = ERRSET_FAIL;
		जाओ fail;
	}

#अगर_घोषित LDNS_DEBUG
	ldns_resolver_set_debug(ldns_res, true);
#पूर्ण_अगर /* LDNS_DEBUG */

	ldns_resolver_set_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	अगर (!pkt || ldns_pkt_ancount(pkt) < 1) {
		परिणाम = ERRSET_FAIL;
		जाओ fail;
	}

	/* initialize rrset */
	rrset = सुस्मृति(1, माप(काष्ठा rrsetinfo));
	अगर (rrset == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_गिनती(rrdata);
	अगर (!rrset->rri_nrdatas) {
		परिणाम = ERRSET_NODATA;
		जाओ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_आकार(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	अगर ((rrset->rri_name = दो_स्मृति(len)) == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}
	स_नकल(rrset->rri_name,
	    ldns_rdf_तथ्य(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	अगर (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} अन्यथा { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_कुंजियाँ = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_गिनती(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		अगर ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_कुंजियाँ)) == LDNS_STATUS_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} अन्यथा {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_कुंजियाँ);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = सुस्मृति(rrset->rri_nrdatas,
	   माप(काष्ठा rdatainfo));

	अगर (rrset->rri_rdatas == शून्य) {
		परिणाम = ERRSET_NOMEMORY;
		जाओ fail;
	}

	/* allocate memory for signatures */
	अगर (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = सुस्मृति(rrset->rri_nsigs,
		    माप(काष्ठा rdatainfo));

		अगर (rrset->rri_sigs == शून्य) {
			परिणाम = ERRSET_NOMEMORY;
			जाओ fail;
		}
	}

	/* copy answers & signatures */
	क्रम (i=0, सूचकांक_ans=0, सूचकांक_sig=0; i< pkt->_header->_ancount; i++) {
		rdata = शून्य;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		अगर (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[सूचकांक_ans++];
		}

		अगर (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[सूचकांक_sig++];
		}

		अगर (rdata) {
			माप_प्रकार rdata_offset = 0;

			rdata->rdi_लंबाई = 0;
			क्रम (j=0; j< rr->rd_गिनती; j++) {
				rdata->rdi_लंबाई +=
				    ldns_rdf_आकार(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_तथ्य = दो_स्मृति(rdata->rdi_लंबाई);
			अगर (rdata->rdi_तथ्य == शून्य) {
				परिणाम = ERRSET_NOMEMORY;
				जाओ fail;
			}

			/* Re-create the raw DNS RDATA */
			क्रम (j=0; j< rr->rd_गिनती; j++) {
				len = ldns_rdf_आकार(ldns_rr_rdf(rr, j));
				स_नकल(rdata->rdi_तथ्य + rdata_offset,
				       ldns_rdf_तथ्य(ldns_rr_rdf(rr, j)), len);
				rdata_offset += len;
			}
		}
	}

	*res = rrset;
	rrset = शून्य; /* transferred */
	परिणाम = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	वापस परिणाम;
}


व्योम
freerrset(काष्ठा rrsetinfo *rrset)
{
	u_int16_t i;

	अगर (rrset == शून्य)
		वापस;

	अगर (rrset->rri_rdatas) {
		क्रम (i = 0; i < rrset->rri_nrdatas; i++) {
			अगर (rrset->rri_rdatas[i].rdi_तथ्य == शून्य)
				अवरोध;
			मुक्त(rrset->rri_rdatas[i].rdi_तथ्य);
		}
		मुक्त(rrset->rri_rdatas);
	}

	अगर (rrset->rri_sigs) {
		क्रम (i = 0; i < rrset->rri_nsigs; i++) {
			अगर (rrset->rri_sigs[i].rdi_तथ्य == शून्य)
				अवरोध;
			मुक्त(rrset->rri_sigs[i].rdi_तथ्य);
		}
		मुक्त(rrset->rri_sigs);
	}

	अगर (rrset->rri_name)
		मुक्त(rrset->rri_name);
	मुक्त(rrset);
}


#पूर्ण_अगर /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
