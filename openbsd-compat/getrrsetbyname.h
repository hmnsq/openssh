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

#अगर_अघोषित _GETRRSETBYNAME_H
#घोषणा _GETRRSETBYNAME_H

#समावेश "includes.h"

#अगर_अघोषित HAVE_GETRRSETBYNAME

#समावेश <sys/types.h>
#समावेश <netinet/in.h>
#समावेश <arpa/nameser.h>
#समावेश <netdb.h>
#समावेश <resolv.h>

#अगर_अघोषित HFIXEDSZ
#घोषणा HFIXEDSZ 12
#पूर्ण_अगर

#अगर_अघोषित T_RRSIG
#घोषणा T_RRSIG 46
#पूर्ण_अगर

/*
 * Flags for getrrsetbyname()
 */
#अगर_अघोषित RRSET_VALIDATED
# define RRSET_VALIDATED	1
#पूर्ण_अगर

/*
 * Return codes for getrrsetbyname()
 */
#अगर_अघोषित ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#पूर्ण_अगर

काष्ठा rdatainfo {
	अचिन्हित पूर्णांक		rdi_लंबाई;	/* length of data */
	अचिन्हित अक्षर		*rdi_तथ्य;	/* record data */
};

काष्ठा rrsetinfo {
	अचिन्हित पूर्णांक		rri_flags;	/* RRSET_VALIDATED ... */
	अचिन्हित पूर्णांक		rri_rdclass;	/* class number */
	अचिन्हित पूर्णांक		rri_rdtype;	/* RR type number */
	अचिन्हित पूर्णांक		rri_ttl;	/* time to live */
	अचिन्हित पूर्णांक		rri_nrdatas;	/* size of rdatas array */
	अचिन्हित पूर्णांक		rri_nsigs;	/* size of sigs array */
	अक्षर			*rri_name;	/* canonical name */
	काष्ठा rdatainfo	*rri_rdatas;	/* individual records */
	काष्ठा rdatainfo	*rri_sigs;	/* individual signatures */
};

पूर्णांक		getrrsetbyname(स्थिर अक्षर *, अचिन्हित पूर्णांक, अचिन्हित पूर्णांक, अचिन्हित पूर्णांक, काष्ठा rrsetinfo **);
व्योम		freerrset(काष्ठा rrsetinfo *);

#पूर्ण_अगर /* !defined(HAVE_GETRRSETBYNAME) */

#पूर्ण_अगर /* _GETRRSETBYNAME_H */
