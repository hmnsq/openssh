/* OPENBSD BASED ON : include/netdb.h */

/* $OpenBSD: getrrsetbyname.c,v 1.4 2001/08/16 18:16:43 ho Exp $ */

/*
 * Copyright (c) 2001 Jakob Schlyter. All rights reserved.
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

#यदि_अपरिभाषितम् _GETRRSETBYNAME_H
#परिभाषय _GETRRSETBYNAME_H

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_GETRRSETBYNAME

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/nameser.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <resolv.h>

#यदि_अपरिभाषितम् HFIXEDSZ
#परिभाषय HFIXEDSZ 12
#यदि_अन्तः

#यदि_अपरिभाषितम् T_RRSIG
#परिभाषय T_RRSIG 46
#यदि_अन्तः

/*
 * Flags for getrrsetbyname()
 */
#यदि_अपरिभाषितम् RRSET_VALIDATED
# define RRSET_VALIDATED	1
#यदि_अन्तः

/*
 * Return codes for getrrsetbyname()
 */
#यदि_अपरिभाषितम् ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#यदि_अन्तः

संरचना rdatainfo {
	अचिह्नित पूर्णाङ्क		rdi_दीर्घता;	/* length of data */
	अचिह्नित वर्ण		*rdi_दत्त;	/* record data */
};

संरचना rrsetinfo {
	अचिह्नित पूर्णाङ्क		rri_flags;	/* RRSET_VALIDATED ... */
	अचिह्नित पूर्णाङ्क		rri_rdclass;	/* class number */
	अचिह्नित पूर्णाङ्क		rri_rdtype;	/* RR type number */
	अचिह्नित पूर्णाङ्क		rri_ttl;	/* time to live */
	अचिह्नित पूर्णाङ्क		rri_nrdatas;	/* size of rdatas array */
	अचिह्नित पूर्णाङ्क		rri_nsigs;	/* size of sigs array */
	वर्ण			*rri_name;	/* canonical name */
	संरचना rdatainfo	*rri_rdatas;	/* individual records */
	संरचना rdatainfo	*rri_sigs;	/* individual signatures */
};

पूर्णाङ्क		getrrsetbyname(ध्रुव वर्ण *, अचिह्नित पूर्णाङ्क, अचिह्नित पूर्णाङ्क, अचिह्नित पूर्णाङ्क, संरचना rrsetinfo **);
शून्य		freerrset(संरचना rrsetinfo *);

#यदि_अन्तः /* !defined(HAVE_GETRRSETBYNAME) */

#यदि_अन्तः /* _GETRRSETBYNAME_H */
