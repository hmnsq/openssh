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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#అన్తర్భావ <sys/types.h>

#నిర్వచితమైతే HAVE_SYS_MOUNT_H
#అన్తర్భావ <sys/mount.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_STATFS_H
#అన్తర్భావ <sys/statfs.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_VFS_H
#అన్తర్భావ <sys/vfs.h>
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FSBLKCNT_T
రకనిర్వచనం గుర్తులేని దీర్ఘ fsblkcnt_t;
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_FSFILCNT_T
రకనిర్వచనం గుర్తులేని దీర్ఘ fsfilcnt_t;
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే ST_RDONLY
#నిర్వచించు ST_RDONLY	1
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే ST_NOSUID
#నిర్వచించు ST_NOSUID	2
#అయితే_ముగింపు

	/* as defined in IEEE Std 1003.1, 2004 Edition */
నిర్మాణం statvfs {
	గుర్తులేని దీర్ఘ f_bsize;	/* File system block size. */
	గుర్తులేని దీర్ఘ f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_ఖండాలు;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	గుర్తులేని దీర్ఘ f_fsid;	/* File system ID. */
	గుర్తులేని దీర్ఘ f_flag;	/* BBit mask of f_flag values. */
	గుర్తులేని దీర్ఘ f_namemax;/*  Maximum filename length. */
};
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_STATVFS
పూర్ణాంకం statvfs(స్థిరరాశి అక్షరం *, నిర్మాణం statvfs *);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_FSTATVFS
పూర్ణాంకం fstatvfs(పూర్ణాంకం, నిర్మాణం statvfs *);
#అయితే_ముగింపు
