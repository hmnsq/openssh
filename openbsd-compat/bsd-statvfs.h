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

#إذا !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ضمن <sys/types.h>

#که_تعریف_شوی HAVE_SYS_MOUNT_H
#ضمن <sys/mount.h>
#د_که_پای
#که_تعریف_شوی HAVE_SYS_STATFS_H
#ضمن <sys/statfs.h>
#د_که_پای
#که_تعریف_شوی HAVE_SYS_VFS_H
#ضمن <sys/vfs.h>
#د_که_پای

#که_نه_تعریف_شوی HAVE_FSBLKCNT_T
تعريفنوع بینښه اوږد fsblkcnt_t;
#د_که_پای
#که_نه_تعریف_شوی HAVE_FSFILCNT_T
تعريفنوع بینښه اوږد fsfilcnt_t;
#د_که_پای

#که_نه_تعریف_شوی ST_RDONLY
#تعریف_کړه ST_RDONLY	1
#د_که_پای
#که_نه_تعریف_شوی ST_NOSUID
#تعریف_کړه ST_NOSUID	2
#د_که_پای

	/* as defined in IEEE Std 1003.1, 2004 Edition */
بنية statvfs {
	بینښه اوږد f_bsize;	/* File system block size. */
	بینښه اوږد f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_بلاکونه;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	بینښه اوږد f_fsid;	/* File system ID. */
	بینښه اوږد f_flag;	/* BBit mask of f_flag values. */
	بینښه اوږد f_namemax;/*  Maximum filename length. */
};
#د_که_پای

#که_نه_تعریف_شوی HAVE_STATVFS
صحيح statvfs(ثابت حرف *, بنية statvfs *);
#د_که_پای

#که_نه_تعریف_شوی HAVE_FSTATVFS
صحيح fstatvfs(صحيح, بنية statvfs *);
#د_که_پای
