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

#ifndef _GETRRSETBYNAME_H
#define _GETRRSETBYNAME_H

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_GETRRSETBYNAME

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/nameser.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <resolv.h>

#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif

#ifndef T_RRSIG
#define T_RRSIG 46
#endif

/*
 * Flags for getrrsetbyname()
 */
#ifndef RRSET_VALIDATED
# define RRSET_VALIDATED	1
#endif

/*
 * Return codes for getrrsetbyname()
 */
#ifndef ERRSET_SUCCESS
# define ERRSET_SUCCESS		0
# define ERRSET_NOMEMORY	1
# define ERRSET_FAIL		2
# define ERRSET_INVAL		3
# define ERRSET_NONAME		4
# define ERRSET_NODATA		5
#endif

સંરચના rdatainfo {
	unsigned પૂર્ણાંક		rdi_length;	/* length of data */
	unsigned અક્ષર		*rdi_data;	/* record data */
};

સંરચના rrsetinfo {
	unsigned પૂર્ણાંક		rri_flags;	/* RRSET_VALIDATED ... */
	unsigned પૂર્ણાંક		rri_rdclass;	/* class number */
	unsigned પૂર્ણાંક		rri_rdtype;	/* RR type number */
	unsigned પૂર્ણાંક		rri_ttl;	/* time to live */
	unsigned પૂર્ણાંક		rri_nrdatas;	/* size of rdatas array */
	unsigned પૂર્ણાંક		rri_nsigs;	/* size of sigs array */
	અક્ષર			*rri_name;	/* canonical name */
	સંરચના rdatainfo	*rri_rdatas;	/* individual records */
	સંરચના rdatainfo	*rri_sigs;	/* individual signatures */
};

પૂર્ણાંક		getrrsetbyname(અચલ અક્ષર *, unsigned પૂર્ણાંક, unsigned પૂર્ણાંક, unsigned પૂર્ણાંક, સંરચના rrsetinfo **);
શૂન્ય		freerrset(સંરચના rrsetinfo *);

#endif /* !defined(HAVE_GETRRSETBYNAME) */

#endif /* _GETRRSETBYNAME_H */
