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

#جے_تعریف_شدہ HAVE_SYS_MOUNT_H
#ضمن <sys/mount.h>
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_STATFS_H
#ضمن <sys/statfs.h>
#جے_انت
#جے_تعریف_شدہ HAVE_SYS_VFS_H
#ضمن <sys/vfs.h>
#جے_انت

#جے_بنا_تعریف HAVE_FSBLKCNT_T
تعريفنوع بنانشانی لما fsblkcnt_t;
#جے_انت
#جے_بنا_تعریف HAVE_FSFILCNT_T
تعريفنوع بنانشانی لما fsfilcnt_t;
#جے_انت

#جے_بنا_تعریف ST_RDONLY
#تعریف_کرو ST_RDONLY	1
#جے_انت
#جے_بنا_تعریف ST_NOSUID
#تعریف_کرو ST_NOSUID	2
#جے_انت

	/* as defined in IEEE Std 1003.1, 2004 Edition */
بنية statvfs {
	بنانشانی لما f_bsize;	/* File system block size. */
	بنانشانی لما f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_بلاکاں;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	بنانشانی لما f_fsid;	/* File system ID. */
	بنانشانی لما f_flag;	/* BBit mask of f_flag values. */
	بنانشانی لما f_namemax;/*  Maximum filename length. */
};
#جے_انت

#جے_بنا_تعریف HAVE_STATVFS
صحيح statvfs(ثابت حرف *, بنية statvfs *);
#جے_انت

#جے_بنا_تعریف HAVE_FSTATVFS
صحيح fstatvfs(صحيح, بنية statvfs *);
#جے_انت
