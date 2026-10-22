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

#شامل "includes.h"

#اگر !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#شامل <sys/types.h>

#اگر_تعریف_شدہ HAVE_SYS_MOUNT_H
#شامل <sys/mount.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_STATFS_H
#شامل <sys/statfs.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SYS_VFS_H
#شامل <sys/vfs.h>
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FSBLKCNT_T
قسمتعریف غیرعلامتی طویل fsblkcnt_t;
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_FSFILCNT_T
قسمتعریف غیرعلامتی طویل fsfilcnt_t;
#اگر_ختم

#اگر_غیر_تعریف_شدہ ST_RDONLY
#تعریف_کرو ST_RDONLY	1
#اگر_ختم
#اگر_غیر_تعریف_شدہ ST_NOSUID
#تعریف_کرو ST_NOSUID	2
#اگر_ختم

	/* as defined in IEEE Std 1003.1, 2004 Edition */
ساخت statvfs {
	غیرعلامتی طویل f_bsize;	/* File system block size. */
	غیرعلامتی طویل f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_بلاکیں;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	غیرعلامتی طویل f_fsid;	/* File system ID. */
	غیرعلامتی طویل f_flag;	/* BBit mask of f_flag values. */
	غیرعلامتی طویل f_namemax;/*  Maximum filename length. */
};
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_STATVFS
صحیح statvfs(ثابت حرف *, ساخت statvfs *);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_FSTATVFS
صحیح fstatvfs(صحیح, ساخت statvfs *);
#اگر_ختم
