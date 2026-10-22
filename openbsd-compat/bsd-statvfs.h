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

#اگر_تعریف_شده HAVE_SYS_MOUNT_H
#ضمن <sys/mount.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_STATFS_H
#ضمن <sys/statfs.h>
#پایان_اگر
#اگر_تعریف_شده HAVE_SYS_VFS_H
#ضمن <sys/vfs.h>
#پایان_اگر

#اگر_تعریف_نشده HAVE_FSBLKCNT_T
تعريفنوع بیعلامت دراز fsblkcnt_t;
#پایان_اگر
#اگر_تعریف_نشده HAVE_FSFILCNT_T
تعريفنوع بیعلامت دراز fsfilcnt_t;
#پایان_اگر

#اگر_تعریف_نشده ST_RDONLY
#تعریف_کن ST_RDONLY	1
#پایان_اگر
#اگر_تعریف_نشده ST_NOSUID
#تعریف_کن ST_NOSUID	2
#پایان_اگر

	/* as defined in IEEE Std 1003.1, 2004 Edition */
بنية statvfs {
	بیعلامت دراز f_bsize;	/* File system block size. */
	بیعلامت دراز f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_بلوکها;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	بیعلامت دراز f_fsid;	/* File system ID. */
	بیعلامت دراز f_flag;	/* BBit mask of f_flag values. */
	بیعلامت دراز f_namemax;/*  Maximum filename length. */
};
#پایان_اگر

#اگر_تعریف_نشده HAVE_STATVFS
صحيح statvfs(ثابت حرف *, بنية statvfs *);
#پایان_اگر

#اگر_تعریف_نشده HAVE_FSTATVFS
صحيح fstatvfs(صحيح, بنية statvfs *);
#پایان_اگر
