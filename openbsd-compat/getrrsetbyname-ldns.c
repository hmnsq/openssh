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

#تعریف_کرو حافظہ_دو(x)	(xmalloc(x))
#تعریف_کرو صفر_حافظہ_دو(x, y)	(xcalloc((x),(y)))

صحیح
getrrsetbyname(ثابت حرف *hostname, غیرعلامتی صحیح rdclass,
	       غیرعلامتی صحیح rdtype, غیرعلامتی صحیح flags,
	       ساخت rrsetinfo **res)
{
	صحیح نتیجہ;
	غیرعلامتی صحیح i, j, اشاریہ_ans, اشاریہ_sig;
	ساخت rrsetinfo *rrset = تہی;
	ساخت rdatainfo *rdata;
	سائز_t len;
	ldns_resolver *ldns_res = تہی;
	ldns_rdf *domain = تہی;
	ldns_pkt *pkt = تہی;
	ldns_rr_list *rrsigs = تہی, *rrdata = تہی;
	ldns_حالت err;
	ldns_rr *rr;

	/* check for invalid class and type */
	اگر (rdclass > 0xffff || rdtype > 0xffff) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* don't allow queries of class or type ANY */
	اگر (rdclass == 0xff || rdtype == 0xff) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* don't allow flags yet, unimplemented */
	اگر (flags) {
		نتیجہ = ERRSET_INVAL;
		جاؤ fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	اگر ((err = ldns_resolver_new_frm_file(&ldns_res, تہی)) != \
	    LDNS_حالت_OK) {
		نتیجہ = ERRSET_FAIL;
		جاؤ fail;
	}

#اگر_تعریف_شدہ LDNS_DEBUG
	ldns_resolver_سیٹ_debug(ldns_res, true);
#اگر_ختم /* LDNS_DEBUG */

	ldns_resolver_سیٹ_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	اگر (!pkt || ldns_pkt_ancount(pkt) < 1) {
		نتیجہ = ERRSET_FAIL;
		جاؤ fail;
	}

	/* initialize rrset */
	rrset = صفر_حافظہ_دو(1, حجم(ساخت rrsetinfo));
	اگر (rrset == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_گنتی(rrdata);
	اگر (!rrset->rri_nrdatas) {
		نتیجہ = ERRSET_NODATA;
		جاؤ fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_سائز(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	اگر ((rrset->rri_name = حافظہ_دو(len)) == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}
	حافظہ_نقل(rrset->rri_name,
	    ldns_rdf_ڈیٹا(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	اگر (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} ورنہ { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_کلیدیں = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_گنتی(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		اگر ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_کلیدیں)) == LDNS_حالت_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} ورنہ {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_کلیدیں);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = صفر_حافظہ_دو(rrset->rri_nrdatas,
	   حجم(ساخت rdatainfo));

	اگر (rrset->rri_rdatas == تہی) {
		نتیجہ = ERRSET_NOMEMORY;
		جاؤ fail;
	}

	/* allocate memory for signatures */
	اگر (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = صفر_حافظہ_دو(rrset->rri_nsigs,
		    حجم(ساخت rdatainfo));

		اگر (rrset->rri_sigs == تہی) {
			نتیجہ = ERRSET_NOMEMORY;
			جاؤ fail;
		}
	}

	/* copy answers & signatures */
	برائے (i=0, اشاریہ_ans=0, اشاریہ_sig=0; i< pkt->سرخی->_ancount; i++) {
		rdata = تہی;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		اگر (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[اشاریہ_ans++];
		}

		اگر (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[اشاریہ_sig++];
		}

		اگر (rdata) {
			سائز_t rdata_انحراف = 0;

			rdata->rdi_لمبائی = 0;
			برائے (j=0; j< rr->rd_گنتی; j++) {
				rdata->rdi_لمبائی +=
				    ldns_rdf_سائز(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_ڈیٹا = حافظہ_دو(rdata->rdi_لمبائی);
			اگر (rdata->rdi_ڈیٹا == تہی) {
				نتیجہ = ERRSET_NOMEMORY;
				جاؤ fail;
			}

			/* Re-create the raw DNS RDATA */
			برائے (j=0; j< rr->rd_گنتی; j++) {
				len = ldns_rdf_سائز(ldns_rr_rdf(rr, j));
				حافظہ_نقل(rdata->rdi_ڈیٹا + rdata_انحراف,
				       ldns_rdf_ڈیٹا(ldns_rr_rdf(rr, j)), len);
				rdata_انحراف += len;
			}
		}
	}

	*res = rrset;
	rrset = تہی; /* transferred */
	نتیجہ = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	واپس نتیجہ;
}


خالی
freerrset(ساخت rrsetinfo *rrset)
{
	u_int16_t i;

	اگر (rrset == تہی)
		واپس;

	اگر (rrset->rri_rdatas) {
		برائے (i = 0; i < rrset->rri_nrdatas; i++) {
			اگر (rrset->rri_rdatas[i].rdi_ڈیٹا == تہی)
				توڑو;
			آزاد(rrset->rri_rdatas[i].rdi_ڈیٹا);
		}
		آزاد(rrset->rri_rdatas);
	}

	اگر (rrset->rri_sigs) {
		برائے (i = 0; i < rrset->rri_nsigs; i++) {
			اگر (rrset->rri_sigs[i].rdi_ڈیٹا == تہی)
				توڑو;
			آزاد(rrset->rri_sigs[i].rdi_ڈیٹا);
		}
		آزاد(rrset->rri_sigs);
	}

	اگر (rrset->rri_name)
		آزاد(rrset->rri_name);
	آزاد(rrset);
}


#اگر_ختم /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
