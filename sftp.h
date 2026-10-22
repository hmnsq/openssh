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

/* version */
#घोषणा	SSH2_FILEXFER_VERSION		3

/* client to server */
#घोषणा SSH2_FXP_INIT			1
#घोषणा SSH2_FXP_OPEN			3
#घोषणा SSH2_FXP_CLOSE			4
#घोषणा SSH2_FXP_READ			5
#घोषणा SSH2_FXP_WRITE			6
#घोषणा SSH2_FXP_LSTAT			7
#घोषणा SSH2_FXP_STAT_VERSION_0		7
#घोषणा SSH2_FXP_FSTAT			8
#घोषणा SSH2_FXP_SETSTAT		9
#घोषणा SSH2_FXP_FSETSTAT		10
#घोषणा SSH2_FXP_OPENDIR		11
#घोषणा SSH2_FXP_READDIR		12
#घोषणा SSH2_FXP_REMOVE			13
#घोषणा SSH2_FXP_MKDIR			14
#घोषणा SSH2_FXP_RMDIR			15
#घोषणा SSH2_FXP_REALPATH		16
#घोषणा SSH2_FXP_STAT			17
#घोषणा SSH2_FXP_RENAME			18
#घोषणा SSH2_FXP_READLINK		19
#घोषणा SSH2_FXP_SYMLINK		20

/* server to client */
#घोषणा SSH2_FXP_VERSION		2
#घोषणा SSH2_FXP_STATUS			101
#घोषणा SSH2_FXP_HANDLE			102
#घोषणा SSH2_FXP_तथ्य			103
#घोषणा SSH2_FXP_NAME			104
#घोषणा SSH2_FXP_ATTRS			105

#घोषणा SSH2_FXP_EXTENDED		200
#घोषणा SSH2_FXP_EXTENDED_REPLY		201

/* attributes */
#घोषणा SSH2_FILEXFER_ATTR_आकार		0x00000001
#घोषणा SSH2_FILEXFER_ATTR_UIDGID	0x00000002
#घोषणा SSH2_FILEXFER_ATTR_PERMISSIONS	0x00000004
#घोषणा SSH2_FILEXFER_ATTR_ACMODTIME	0x00000008
#घोषणा SSH2_FILEXFER_ATTR_EXTENDED	0x80000000

/* portable open modes */
#घोषणा SSH2_FXF_READ			0x00000001
#घोषणा SSH2_FXF_WRITE			0x00000002
#घोषणा SSH2_FXF_APPEND			0x00000004
#घोषणा SSH2_FXF_CREAT			0x00000008
#घोषणा SSH2_FXF_TRUNC			0x00000010
#घोषणा SSH2_FXF_EXCL			0x00000020

/* statvfs@openssh.com f_flag flags */
#घोषणा SSH2_FXE_STATVFS_ST_RDONLY	0x00000001
#घोषणा SSH2_FXE_STATVFS_ST_NOSUID	0x00000002

/* status messages */
#घोषणा SSH2_FX_OK			0
#घोषणा SSH2_FX_EOF			1
#घोषणा SSH2_FX_NO_SUCH_FILE		2
#घोषणा SSH2_FX_PERMISSION_DENIED	3
#घोषणा SSH2_FX_FAILURE			4
#घोषणा SSH2_FX_BAD_MESSAGE		5
#घोषणा SSH2_FX_NO_CONNECTION		6
#घोषणा SSH2_FX_CONNECTION_LOST		7
#घोषणा SSH2_FX_OP_UNSUPPORTED		8
#घोषणा SSH2_FX_MAX			8

काष्ठा passwd;

पूर्णांक	sftp_server_main(पूर्णांक, अक्षर **, काष्ठा passwd *);
व्योम	sftp_server_cleanup_exit(पूर्णांक) __attribute__((noreturn));
