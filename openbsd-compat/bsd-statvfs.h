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

#جيڪڏهن_وصف_ٿيل HAVE_SYS_MOUNT_H
#ضمن <sys/mount.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_STATFS_H
#ضمن <sys/statfs.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_VFS_H
#ضمن <sys/vfs.h>
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FSBLKCNT_T
تعريفنوع بنانشان ڊگهو fsblkcnt_t;
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل HAVE_FSFILCNT_T
تعريفنوع بنانشان ڊگهو fsfilcnt_t;
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل ST_RDONLY
#وصف_ڪريو ST_RDONLY	1
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل ST_NOSUID
#وصف_ڪريو ST_NOSUID	2
#جيڪڏهن_پورو

	/* as defined in IEEE Std 1003.1, 2004 Edition */
بنية statvfs {
	بنانشان ڊگهو f_bsize;	/* File system block size. */
	بنانشان ڊگهو f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_بلاڪون;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	بنانشان ڊگهو f_fsid;	/* File system ID. */
	بنانشان ڊگهو f_flag;	/* BBit mask of f_flag values. */
	بنانشان ڊگهو f_namemax;/*  Maximum filename length. */
};
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_STATVFS
صحيح statvfs(ثابت حرف *, بنية statvfs *);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_FSTATVFS
صحيح fstatvfs(صحيح, بنية statvfs *);
#جيڪڏهن_پورو
