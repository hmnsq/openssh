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
#define SFTP_MAX_સંદેશ_LENGTH	(256 * 1024)

સંરચના sshbuf;
પ્રકારવ્યાખ્યા સંરચના Attrib Attrib;

/* File attributes */
સંરચના Attrib {
	uint32_t	flags;
	uint64_t	size;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	perm;
	uint32_t	atime;
	uint32_t	mtime;
};

શૂન્ય	 attrib_clear(Attrib *);
શૂન્ય	 stat_to_attrib(અચલ સંરચના stat *, Attrib *);
શૂન્ય	 attrib_to_stat(અચલ Attrib *, સંરચના stat *);
પૂર્ણાંક	 decode_attrib(સંરચના sshbuf *, Attrib *);
પૂર્ણાંક	 encode_attrib(સંરચના sshbuf *, અચલ Attrib *);
અક્ષર	*ls_file(અચલ અક્ષર *, અચલ સંરચના stat *, પૂર્ણાંક, પૂર્ણાંક,
    અચલ અક્ષર *, અચલ અક્ષર *);

અચલ અક્ષર *fx2txt(પૂર્ણાંક);
