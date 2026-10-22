/*
 * Copyright (c) 2008,2014 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#समावेश "includes.h"

#अगर !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#समावेश <sys/types.h>

#अगर_घोषित HAVE_SYS_MOUNT_H
#समावेश <sys/mount.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_STATFS_H
#समावेश <sys/statfs.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SYS_VFS_H
#समावेश <sys/vfs.h>
#पूर्ण_अगर

#अगर_अघोषित HAVE_FSBLKCNT_T
प्रकार अचिन्हित दीर्घ fsblkcnt_t;
#पूर्ण_अगर
#अगर_अघोषित HAVE_FSFILCNT_T
प्रकार अचिन्हित दीर्घ fsfilcnt_t;
#पूर्ण_अगर

#अगर_अघोषित ST_RDONLY
#घोषणा ST_RDONLY	1
#पूर्ण_अगर
#अगर_अघोषित ST_NOSUID
#घोषणा ST_NOSUID	2
#पूर्ण_अगर

	/* as defined in IEEE Std 1003.1, 2004 Edition */
काष्ठा statvfs {
	अचिन्हित दीर्घ f_bsize;	/* File system block size. */
	अचिन्हित दीर्घ f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_blocks;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	अचिन्हित दीर्घ f_fsid;	/* File system ID. */
	अचिन्हित दीर्घ f_flag;	/* BBit mask of f_flag values. */
	अचिन्हित दीर्घ f_namemax;/*  Maximum filename length. */
};
#पूर्ण_अगर

#अगर_अघोषित HAVE_STATVFS
पूर्णांक statvfs(स्थिर अक्षर *, काष्ठा statvfs *);
#पूर्ण_अगर

#अगर_अघोषित HAVE_FSTATVFS
पूर्णांक fstatvfs(पूर्णांक, काष्ठा statvfs *);
#पूर्ण_अगर
