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

/*संस्करणम्*/
#परिभाषय	SSH2_FILEXFER_संस्करणम्		3

/* client to server */
#परिभाषय SSH2_FXP_INIT			1
#परिभाषय SSH2_FXP_OPEN			3
#परिभाषय SSH2_FXP_CLOSE			4
#परिभाषय SSH2_FXP_READ			5
#परिभाषय SSH2_FXP_WRITE			6
#परिभाषय SSH2_FXP_LSTAT			7
#परिभाषय SSH2_FXP_STAT_संस्करणम्_0		7
#परिभाषय SSH2_FXP_FSTAT			8
#परिभाषय SSH2_FXP_SETSTAT		9
#परिभाषय SSH2_FXP_FSETSTAT		10
#परिभाषय SSH2_FXP_OPENDIR		11
#परिभाषय SSH2_FXP_READDIR		12
#परिभाषय SSH2_FXP_REMOVE			13
#परिभाषय SSH2_FXP_MKDIR			14
#परिभाषय SSH2_FXP_RMDIR			15
#परिभाषय SSH2_FXP_REALPATH		16
#परिभाषय SSH2_FXP_STAT			17
#परिभाषय SSH2_FXP_RENAME			18
#परिभाषय SSH2_FXP_READLINK		19
#परिभाषय SSH2_FXP_SYMLINK		20

/* server to client */
#परिभाषय SSH2_FXP_संस्करणम्		2
#परिभाषय SSH2_FXP_स्थितिः			101
#परिभाषय SSH2_FXP_HANDLE			102
#परिभाषय SSH2_FXP_दत्त			103
#परिभाषय SSH2_FXP_NAME			104
#परिभाषय SSH2_FXP_ATTRS			105

#परिभाषय SSH2_FXP_EXTENDED		200
#परिभाषय SSH2_FXP_EXTENDED_प्रत्युत्तरम्		201

/*गुणाः*/
#परिभाषय SSH2_FILEXFER_ATTR_आकार		0x00000001
#परिभाषय SSH2_FILEXFER_ATTR_UIDGID	0x00000002
#परिभाषय SSH2_FILEXFER_ATTR_PERMISSIONS	0x00000004
#परिभाषय SSH2_FILEXFER_ATTR_ACMODTIME	0x00000008
#परिभाषय SSH2_FILEXFER_ATTR_EXTENDED	0x80000000

/* portable open modes */
#परिभाषय SSH2_FXF_READ			0x00000001
#परिभाषय SSH2_FXF_WRITE			0x00000002
#परिभाषय SSH2_FXF_APPEND			0x00000004
#परिभाषय SSH2_FXF_CREAT			0x00000008
#परिभाषय SSH2_FXF_TRUNC			0x00000010
#परिभाषय SSH2_FXF_EXCL			0x00000020

/* statvfs@openssh.com f_flag flags */
#परिभाषय SSH2_FXE_STATVFS_ST_RDONLY	0x00000001
#परिभाषय SSH2_FXE_STATVFS_ST_NOSUID	0x00000002

/* status messages */
#परिभाषय SSH2_FX_OK			0
#परिभाषय SSH2_FX_EOF			1
#परिभाषय SSH2_FX_NO_SUCH_FILE		2
#परिभाषय SSH2_FX_PERMISSION_DENIED	3
#परिभाषय SSH2_FX_FAILURE			4
#परिभाषय SSH2_FX_BAD_सन्देशः		5
#परिभाषय SSH2_FX_NO_CONNECTION		6
#परिभाषय SSH2_FX_CONNECTION_नष्टम्		7
#परिभाषय SSH2_FX_OP_UNSUPPORTED		8
#परिभाषय SSH2_FX_MAX			8

संरचना passwd;

पूर्णाङ्क	sftp_server_main(पूर्णाङ्क, वर्ण **, संरचना passwd *);
शून्य	sftp_server_cleanup_exit(पूर्णाङ्क) __attribute__((noreturn));
