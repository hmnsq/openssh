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
#تعریف_کرو SFTP_MAX_پیغام_لمائی	(256 * 1024)

بنية sshbuf;
تعريفنوع بنية Attrib Attrib;

/* File attributes */
بنية Attrib {
	uint32_t	flags;
	uint64_t	ناپ;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	perm;
	uint32_t	atime;
	uint32_t	mtime;
};

فراغ	 attrib_clear(Attrib *);
فراغ	 stat_منزل_attrib(ثابت بنية stat *, Attrib *);
فراغ	 attrib_منزل_stat(ثابت Attrib *, بنية stat *);
صحيح	 decode_attrib(بنية sshbuf *, Attrib *);
صحيح	 encode_attrib(بنية sshbuf *, ثابت Attrib *);
حرف	*ls_file(ثابت حرف *, ثابت بنية stat *, صحيح, صحيح,
    ثابت حرف *, ثابت حرف *);

ثابت حرف *fx2txt(صحيح);
