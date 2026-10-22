/* $OpenBSD: sftp.h,v 1.9 2008/06/13 00:12:02 dtucker Exp $ */

/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

/*
 * draft-ietf-secsh-filexfer-01.txt
 */

/*సంస్కరణ*/
#నిర్వచించు	SSH2_FILEXFER_సంస్కరణ		3

/* client to server */
#నిర్వచించు SSH2_FXP_INIT			1
#నిర్వచించు SSH2_FXP_OPEN			3
#నిర్వచించు SSH2_FXP_CLOSE			4
#నిర్వచించు SSH2_FXP_READ			5
#నిర్వచించు SSH2_FXP_WRITE			6
#నిర్వచించు SSH2_FXP_LSTAT			7
#నిర్వచించు SSH2_FXP_STAT_సంస్కరణ_0		7
#నిర్వచించు SSH2_FXP_FSTAT			8
#నిర్వచించు SSH2_FXP_SETSTAT		9
#నిర్వచించు SSH2_FXP_FSETSTAT		10
#నిర్వచించు SSH2_FXP_OPENDIR		11
#నిర్వచించు SSH2_FXP_READDIR		12
#నిర్వచించు SSH2_FXP_REMOVE			13
#నిర్వచించు SSH2_FXP_MKDIR			14
#నిర్వచించు SSH2_FXP_RMDIR			15
#నిర్వచించు SSH2_FXP_REALPATH		16
#నిర్వచించు SSH2_FXP_STAT			17
#నిర్వచించు SSH2_FXP_RENAME			18
#నిర్వచించు SSH2_FXP_READLINK		19
#నిర్వచించు SSH2_FXP_SYMLINK		20

/* server to client */
#నిర్వచించు SSH2_FXP_సంస్కరణ		2
#నిర్వచించు SSH2_FXP_స్థితి			101
#నిర్వచించు SSH2_FXP_HANDLE			102
#నిర్వచించు SSH2_FXP_దత్తాంశం			103
#నిర్వచించు SSH2_FXP_NAME			104
#నిర్వచించు SSH2_FXP_ATTRS			105

#నిర్వచించు SSH2_FXP_EXTENDED		200
#నిర్వచించు SSH2_FXP_EXTENDED_జవాబు		201

/*లక్షణాలు*/
#నిర్వచించు SSH2_FILEXFER_ATTR_కొలత		0x00000001
#నిర్వచించు SSH2_FILEXFER_ATTR_UIDGID	0x00000002
#నిర్వచించు SSH2_FILEXFER_ATTR_PERMISSIONS	0x00000004
#నిర్వచించు SSH2_FILEXFER_ATTR_ACMODTIME	0x00000008
#నిర్వచించు SSH2_FILEXFER_ATTR_EXTENDED	0x80000000

/* portable open modes */
#నిర్వచించు SSH2_FXF_READ			0x00000001
#నిర్వచించు SSH2_FXF_WRITE			0x00000002
#నిర్వచించు SSH2_FXF_APPEND			0x00000004
#నిర్వచించు SSH2_FXF_CREAT			0x00000008
#నిర్వచించు SSH2_FXF_TRUNC			0x00000010
#నిర్వచించు SSH2_FXF_EXCL			0x00000020

/* statvfs@openssh.com f_flag flags */
#నిర్వచించు SSH2_FXE_STATVFS_ST_RDONLY	0x00000001
#నిర్వచించు SSH2_FXE_STATVFS_ST_NOSUID	0x00000002

/* status messages */
#నిర్వచించు SSH2_FX_OK			0
#నిర్వచించు SSH2_FX_EOF			1
#నిర్వచించు SSH2_FX_NO_SUCH_FILE		2
#నిర్వచించు SSH2_FX_PERMISSION_DENIED	3
#నిర్వచించు SSH2_FX_FAILURE			4
#నిర్వచించు SSH2_FX_BAD_సందేశం		5
#నిర్వచించు SSH2_FX_NO_CONNECTION		6
#నిర్వచించు SSH2_FX_CONNECTION_కోల్పోయిన		7
#నిర్వచించు SSH2_FX_OP_UNSUPPORTED		8
#నిర్వచించు SSH2_FX_MAX			8

నిర్మాణం passwd;

పూర్ణాంకం	sftp_server_main(పూర్ణాంకం, అక్షరం **, నిర్మాణం passwd *);
శూన్య	sftp_server_cleanup_exit(పూర్ణాంకం) __attribute__((noreturn));
