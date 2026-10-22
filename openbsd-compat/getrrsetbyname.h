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

#اگر_تعریف_نشده _GETRRSETBYNAME_H
#تعریف_کن _GETRRSETBYNAME_H

#ضمن "includes.h"

#اگر_تعریف_نشده HAVE_GETRRSETBYNAME

#ضمن <sys/types.h>
#ضمن <netinet/in.h>
#ضمن <arpa/nameser.h>
#ضمن <netdb.h>
#ضمن <resolv.h>

#اگر_تعریف_نشده HFIXEDSZ
#تعریف_کن HFIXEDSZ 12
#پایان_اگر

#اگر_تعریف_نشده T_RRSIG
#تعریف_کن T_RRSIG 46
#پایان_اگر

/*
 * Flags for getrrsetbyname()
 */
#اگر_تعریف_نشده RRSET_VALIDATED
# define RRSET_VALIDATED	1
#پایان_اگر

/*
 * Return codes for getrrsetbyname()
 */
#اگر_تعریف_نشده ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#پایان_اگر

بنية rdatainfo {
	بیعلامت صحيح		rdi_درازی;	/* length of data */
	بیعلامت حرف		*rdi_داده;	/* record data */
};

بنية rrsetinfo {
	بیعلامت صحيح		rri_flags;	/* RRSET_VALIDATED ... */
	بیعلامت صحيح		rri_rdclass;	/* class number */
	بیعلامت صحيح		rri_rdtype;	/* RR type number */
	بیعلامت صحيح		rri_ttl;	/* time to live */
	بیعلامت صحيح		rri_nrdatas;	/* size of rdatas array */
	بیعلامت صحيح		rri_nsigs;	/* size of sigs array */
	حرف			*rri_name;	/* canonical name */
	بنية rdatainfo	*rri_rdatas;	/* individual records */
	بنية rdatainfo	*rri_sigs;	/* individual signatures */
};

صحيح		getrrsetbyname(ثابت حرف *, بیعلامت صحيح, بیعلامت صحيح, بیعلامت صحيح, بنية rrsetinfo **);
فراغ		freerrset(بنية rrsetinfo *);

#پایان_اگر /* !defined(HAVE_GETRRSETBYNAME) */

#پایان_اگر /* _GETRRSETBYNAME_H */
