/* $OpenBSD: sftp-common.h,v 1.14 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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

/* Maximum packet that we are willing to send/accept */
#నిర్వచించు SFTP_MAX_సందేశం_నిడివి	(256 * 1024)

నిర్మాణం sshbuf;
రకనిర్వచనం నిర్మాణం Attrib Attrib;

/* File attributes */
నిర్మాణం Attrib {
	uint32_t	flags;
	uint64_t	కొలత;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	perm;
	uint32_t	atime;
	uint32_t	mtime;
};

శూన్య	 attrib_clear(Attrib *);
శూన్య	 stat_గమ్యం_attrib(స్థిరరాశి నిర్మాణం stat *, Attrib *);
శూన్య	 attrib_గమ్యం_stat(స్థిరరాశి Attrib *, నిర్మాణం stat *);
పూర్ణాంకం	 decode_attrib(నిర్మాణం sshbuf *, Attrib *);
పూర్ణాంకం	 encode_attrib(నిర్మాణం sshbuf *, స్థిరరాశి Attrib *);
అక్షరం	*ls_file(స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం stat *, పూర్ణాంకం, పూర్ణాంకం,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

స్థిరరాశి అక్షరం *fx2txt(పూర్ణాంకం);
