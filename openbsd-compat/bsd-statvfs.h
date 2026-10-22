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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_MOUNT_H
#ಅನ್ತರ್ಭಾವ <sys/mount.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_STATFS_H
#ಅನ್ತರ್ಭಾವ <sys/statfs.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_VFS_H
#ಅನ್ತರ್ಭಾವ <sys/vfs.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FSBLKCNT_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ fsblkcnt_t;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FSFILCNT_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ fsfilcnt_t;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ST_RDONLY
#ವ್ಯಾಖ್ಯಾನಿಸು ST_RDONLY	1
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ST_NOSUID
#ವ್ಯಾಖ್ಯಾನಿಸು ST_NOSUID	2
#ಆದರೆ_ಅಂತ್ಯ

	/* as defined in IEEE Std 1003.1, 2004 Edition */
ರಚನೆ statvfs {
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ f_bsize;	/* File system block size. */
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_ಖಂಡಗಳು;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ f_fsid;	/* File system ID. */
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ f_flag;	/* BBit mask of f_flag values. */
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ f_namemax;/*  Maximum filename length. */
};
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STATVFS
ಪೂರ್ಣಾಂಕ statvfs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ statvfs *);
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FSTATVFS
ಪೂರ್ಣಾಂಕ fstatvfs(ಪೂರ್ಣಾಂಕ, ರಚನೆ statvfs *);
#ಆದರೆ_ಅಂತ್ಯ
