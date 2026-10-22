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

#جے_بنا_تعریف _GETRRSETBYNAME_H
#تعریف_کرو _GETRRSETBYNAME_H

#ضمن "includes.h"

#جے_بنا_تعریف HAVE_GETRRSETBYNAME

#ضمن <sys/types.h>
#ضمن <netinet/in.h>
#ضمن <arpa/nameser.h>
#ضمن <netdb.h>
#ضمن <resolv.h>

#جے_بنا_تعریف HFIXEDSZ
#تعریف_کرو HFIXEDSZ 12
#جے_انت

#جے_بنا_تعریف T_RRSIG
#تعریف_کرو T_RRSIG 46
#جے_انت

/*
 * Flags for getrrsetbyname()
 */
#جے_بنا_تعریف RRSET_VALIDATED
# define RRSET_VALIDATED	1
#جے_انت

/*
 * Return codes for getrrsetbyname()
 */
#جے_بنا_تعریف ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#جے_انت

بنية rdatainfo {
	بنانشانی صحيح		rdi_لمائی;	/* length of data */
	بنانشانی حرف		*rdi_انکڑے;	/* record data */
};

بنية rrsetinfo {
	بنانشانی صحيح		rri_flags;	/* RRSET_VALIDATED ... */
	بنانشانی صحيح		rri_rdclass;	/* class number */
	بنانشانی صحيح		rri_rdtype;	/* RR type number */
	بنانشانی صحيح		rri_ttl;	/* time to live */
	بنانشانی صحيح		rri_nrdatas;	/* size of rdatas array */
	بنانشانی صحيح		rri_nsigs;	/* size of sigs array */
	حرف			*rri_name;	/* canonical name */
	بنية rdatainfo	*rri_rdatas;	/* individual records */
	بنية rdatainfo	*rri_sigs;	/* individual signatures */
};

صحيح		getrrsetbyname(ثابت حرف *, بنانشانی صحيح, بنانشانی صحيح, بنانشانی صحيح, بنية rrsetinfo **);
فراغ		freerrset(بنية rrsetinfo *);

#جے_انت /* !defined(HAVE_GETRRSETBYNAME) */

#جے_انت /* _GETRRSETBYNAME_H */
