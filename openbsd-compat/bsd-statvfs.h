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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_MOUNT_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mount.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_STATFS_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/statfs.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_VFS_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/vfs.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FSBLKCNT_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ fsblkcnt_t;
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FSFILCNT_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ fsfilcnt_t;
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ST_RDONLY
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ST_RDONLY	1
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ST_NOSUID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ST_NOSUID	2
#ਜੇ_ਅੰਤ

	/* as defined in IEEE Std 1003.1, 2004 Edition */
ਬਣਤਰ statvfs {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ f_bsize;	/* File system block size. */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_ਖੰਡਾਂ;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ f_fsid;	/* File system ID. */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ f_flag;	/* BBit mask of f_flag values. */
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ f_namemax;/*  Maximum filename length. */
};
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STATVFS
ਪੂਰਨ statvfs(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ statvfs *);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FSTATVFS
ਪੂਰਨ fstatvfs(ਪੂਰਨ, ਬਣਤਰ statvfs *);
#ਜੇ_ਅੰਤ
