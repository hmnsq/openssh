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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _GETRRSETBYNAME_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _GETRRSETBYNAME_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETRRSETBYNAME

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/nameser.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <resolv.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HFIXEDSZ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HFIXEDSZ 12
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ T_RRSIG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ T_RRSIG 46
#ਜੇ_ਅੰਤ

/*
 * Flags for getrrsetbyname()
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ RRSET_VALIDATED
# define RRSET_VALIDATED	1
#ਜੇ_ਅੰਤ

/*
 * Return codes for getrrsetbyname()
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#ਜੇ_ਅੰਤ

ਬਣਤਰ rdatainfo {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rdi_ਲੰਮਾਈ;	/* length of data */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ		*rdi_ਅੰਕੜੇ;	/* record data */
};

ਬਣਤਰ rrsetinfo {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_flags;	/* RRSET_VALIDATED ... */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_rdclass;	/* class number */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_rdtype;	/* RR type number */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_ttl;	/* time to live */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_nrdatas;	/* size of rdatas array */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ		rri_nsigs;	/* size of sigs array */
	ਅੱਖਰ			*rri_name;	/* canonical name */
	ਬਣਤਰ rdatainfo	*rri_rdatas;	/* individual records */
	ਬਣਤਰ rdatainfo	*rri_sigs;	/* individual signatures */
};

ਪੂਰਨ		getrrsetbyname(ਅਚਲ ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ, ਬਣਤਰ rrsetinfo **);
ਖਾਲੀ		freerrset(ਬਣਤਰ rrsetinfo *);

#ਜੇ_ਅੰਤ /* !defined(HAVE_GETRRSETBYNAME) */

#ਜੇ_ਅੰਤ /* _GETRRSETBYNAME_H */
