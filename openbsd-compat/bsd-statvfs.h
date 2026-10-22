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

#ضمن "includes.h"

#ܐܢ !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ضمن <sys/types.h>

#ifdef HAVE_SYS_MOUNT_H
#ضمن <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#ضمن <sys/statfs.h>
#endif
#ifdef HAVE_SYS_VFS_H
#ضمن <sys/vfs.h>
#endif

#ifndef HAVE_FSBLKCNT_T
تعريفنوع unsigned long fsblkcnt_t;
#endif
#ifndef HAVE_FSFILCNT_T
تعريفنوع unsigned long fsfilcnt_t;
#endif

#ifndef ST_RDONLY
#define ST_RDONLY	1
#endif
#ifndef ST_NOSUID
#define ST_NOSUID	2
#endif

	/* as defined in IEEE Std 1003.1, 2004 Edition */
بنية statvfs {
	unsigned long f_bsize;	/* File system block size. */
	unsigned long f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_blocks;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	unsigned long f_fsid;	/* File system ID. */
	unsigned long f_flag;	/* BBit mask of f_flag values. */
	unsigned long f_namemax;/*  Maximum filename length. */
};
#endif

#ifndef HAVE_STATVFS
صحيح statvfs(ثابت حرف *, بنية statvfs *);
#endif

#ifndef HAVE_FSTATVFS
صحيح fstatvfs(صحيح, بنية statvfs *);
#endif
