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

#ضمن "includes.h"

#إذا !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS)

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <ldns/ldns.h>

#ضمن "getrrsetbyname.h"
#ضمن "log.h"
#ضمن "xmalloc.h"

#تعریف_کن حافظه_بده(x)	(xmalloc(x))
#تعریف_کن حافظه_صفر_بده(x, y)	(xcalloc((x),(y)))

صحيح
getrrsetbyname(ثابت حرف *hostname, بیعلامت صحيح rdclass,
	       بیعلامت صحيح rdtype, بیعلامت صحيح flags,
	       بنية rrsetinfo **res)
{
	صحيح نتیجه;
	بیعلامت صحيح i, j, شاخص_ans, شاخص_sig;
	بنية rrsetinfo *rrset = عدم;
	بنية rdatainfo *rdata;
	اندازه_t len;
	ldns_resolver *ldns_res = عدم;
	ldns_rdf *domain = عدم;
	ldns_pkt *pkt = عدم;
	ldns_rr_list *rrsigs = عدم, *rrdata = عدم;
	ldns_وضعیت err;
	ldns_rr *rr;

	/* check for invalid class and type */
	إذا (rdclass > 0xffff || rdtype > 0xffff) {
		نتیجه = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow queries of class or type ANY */
	إذا (rdclass == 0xff || rdtype == 0xff) {
		نتیجه = ERRSET_INVAL;
		اذهب fail;
	}

	/* don't allow flags yet, unimplemented */
	إذا (flags) {
		نتیجه = ERRSET_INVAL;
		اذهب fail;
	}

	/* Initialize resolver from resolv.conf */
	domain = ldns_dname_new_frm_str(hostname);
	إذا ((err = ldns_resolver_new_frm_file(&ldns_res, عدم)) != \
	    LDNS_وضعیت_OK) {
		نتیجه = ERRSET_FAIL;
		اذهب fail;
	}

#اگر_تعریف_شده LDNS_DEBUG
	ldns_resolver_مجموعه_debug(ldns_res, true);
#پایان_اگر /* LDNS_DEBUG */

	ldns_resolver_مجموعه_dnssec(ldns_res, true); /* Use DNSSEC */

	/* make query */
	pkt = ldns_resolver_query(ldns_res, domain, rdtype, rdclass, LDNS_RD);

	/*** TODO: finer errcodes -- see original **/
	إذا (!pkt || ldns_pkt_ancount(pkt) < 1) {
		نتیجه = ERRSET_FAIL;
		اذهب fail;
	}

	/* initialize rrset */
	rrset = حافظه_صفر_بده(1, حجم(بنية rrsetinfo));
	إذا (rrset == عدم) {
		نتیجه = ERRSET_NOMEMORY;
		اذهب fail;
	}

	rrdata = ldns_pkt_rr_list_by_type(pkt, rdtype, LDNS_SECTION_ANSWER);
	rrset->rri_nrdatas = ldns_rr_list_rr_شمار(rrdata);
	إذا (!rrset->rri_nrdatas) {
		نتیجه = ERRSET_NODATA;
		اذهب fail;
	}

	/* copy name from answer section */
	len = ldns_rdf_اندازه(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0)));
	إذا ((rrset->rri_name = حافظه_بده(len)) == عدم) {
		نتیجه = ERRSET_NOMEMORY;
		اذهب fail;
	}
	کپی_حافظه(rrset->rri_name,
	    ldns_rdf_داده(ldns_rr_owner(ldns_rr_list_rr(rrdata, 0))), len);

	rrset->rri_rdclass = ldns_rr_get_class(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_rdtype = ldns_rr_get_type(ldns_rr_list_rr(rrdata, 0));
	rrset->rri_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrdata, 0));

	debug2("ldns: got %u answers from DNS", rrset->rri_nrdatas);

	/* Check for authenticated data */
	إذا (ldns_pkt_ad(pkt)) {
		rrset->rri_flags |= RRSET_VALIDATED;
	} وإلا { /* AD is not set, try autonomous validation */
		ldns_rr_list * trusted_کلیدها = ldns_rr_list_new();

		debug2("ldns: trying to validate RRset");
		/* Get eventual sigs */
		rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
		    LDNS_SECTION_ANSWER);

		rrset->rri_nsigs = ldns_rr_list_rr_شمار(rrsigs);
		debug2("ldns: got %u signature(s) (RRTYPE %u) from DNS",
		       rrset->rri_nsigs, LDNS_RR_TYPE_RRSIG);

		إذا ((err = ldns_verify_trusted(ldns_res, rrdata, rrsigs,
		     trusted_کلیدها)) == LDNS_وضعیت_OK) {
			rrset->rri_flags |= RRSET_VALIDATED;
			debug2("ldns: RRset is signed with a valid key");
		} وإلا {
			debug2("ldns: RRset validation failed: %s",
			    ldns_get_errorstr_by_id(err));
		}

		ldns_rr_list_deep_free(trusted_کلیدها);
	}

	/* allocate memory for answers */
	rrset->rri_rdatas = حافظه_صفر_بده(rrset->rri_nrdatas,
	   حجم(بنية rdatainfo));

	إذا (rrset->rri_rdatas == عدم) {
		نتیجه = ERRSET_NOMEMORY;
		اذهب fail;
	}

	/* allocate memory for signatures */
	إذا (rrset->rri_nsigs > 0) {
		rrset->rri_sigs = حافظه_صفر_بده(rrset->rri_nsigs,
		    حجم(بنية rdatainfo));

		إذا (rrset->rri_sigs == عدم) {
			نتیجه = ERRSET_NOMEMORY;
			اذهب fail;
		}
	}

	/* copy answers & signatures */
	لكل (i=0, شاخص_ans=0, شاخص_sig=0; i< pkt->سرآیند->_ancount; i++) {
		rdata = عدم;
		rr = ldns_rr_list_rr(ldns_pkt_answer(pkt), i);

		إذا (ldns_rr_get_class(rr) == rrset->rri_rdclass &&
		    ldns_rr_get_type(rr) == rrset->rri_rdtype) {
			rdata = &rrset->rri_rdatas[شاخص_ans++];
		}

		إذا (rr->_rr_class == rrset->rri_rdclass &&
		    rr->_rr_type == LDNS_RR_TYPE_RRSIG &&
		    rrset->rri_sigs) {
			rdata = &rrset->rri_sigs[شاخص_sig++];
		}

		إذا (rdata) {
			اندازه_t rdata_جابه_جایی = 0;

			rdata->rdi_درازی = 0;
			لكل (j=0; j< rr->rd_شمار; j++) {
				rdata->rdi_درازی +=
				    ldns_rdf_اندازه(ldns_rr_rdf(rr, j));
			}

			rdata->rdi_داده = حافظه_بده(rdata->rdi_درازی);
			إذا (rdata->rdi_داده == عدم) {
				نتیجه = ERRSET_NOMEMORY;
				اذهب fail;
			}

			/* Re-create the raw DNS RDATA */
			لكل (j=0; j< rr->rd_شمار; j++) {
				len = ldns_rdf_اندازه(ldns_rr_rdf(rr, j));
				کپی_حافظه(rdata->rdi_داده + rdata_جابه_جایی,
				       ldns_rdf_داده(ldns_rr_rdf(rr, j)), len);
				rdata_جابه_جایی += len;
			}
		}
	}

	*res = rrset;
	rrset = عدم; /* transferred */
	نتیجه = ERRSET_SUCCESS;

fail:
	freerrset(rrset);
	ldns_rdf_deep_free(domain);
	ldns_pkt_free(pkt);
	ldns_rr_list_deep_free(rrsigs);
	ldns_rr_list_deep_free(rrdata);
	ldns_resolver_deep_free(ldns_res);

	أرجع نتیجه;
}


فراغ
freerrset(بنية rrsetinfo *rrset)
{
	u_int16_t i;

	إذا (rrset == عدم)
		أرجع;

	إذا (rrset->rri_rdatas) {
		لكل (i = 0; i < rrset->rri_nrdatas; i++) {
			إذا (rrset->rri_rdatas[i].rdi_داده == عدم)
				اكسر;
			حرر(rrset->rri_rdatas[i].rdi_داده);
		}
		حرر(rrset->rri_rdatas);
	}

	إذا (rrset->rri_sigs) {
		لكل (i = 0; i < rrset->rri_nsigs; i++) {
			إذا (rrset->rri_sigs[i].rdi_داده == عدم)
				اكسر;
			حرر(rrset->rri_sigs[i].rdi_داده);
		}
		حرر(rrset->rri_sigs);
	}

	إذا (rrset->rri_name)
		حرر(rrset->rri_name);
	حرر(rrset);
}


#پایان_اگر /* !defined (HAVE_GETRRSETBYNAME) && defined (HAVE_LDNS) */
