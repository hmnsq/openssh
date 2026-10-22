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

#నిర్వచితమైతే HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>

#నిర్వచితం_కాకపోతే MNAMELEN
# define MNAMELEN 32
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_STRUCT_STATFS
స్థిర శూన్య
copy_statfs_గమ్యం_statvfs(నిర్మాణం statvfs *గమ్యం, నిర్మాణం statfs *from)
{
	గమ్యం->f_bsize = from->f_bsize;
	గమ్యం->f_frsize = from->f_bsize;	/* no exact equivalent */
	గమ్యం->f_ఖండాలు = from->f_ఖండాలు;
	గమ్యం->f_bfree = from->f_bfree;
	గమ్యం->f_bavail = from->f_bavail;
	గమ్యం->f_files = from->f_files;
	గమ్యం->f_ffree = from->f_ffree;
	గమ్యం->f_favail = from->f_ffree;	/* no exact equivalent */
	గమ్యం->f_fsid = 0;			/* XXX fix me */
#నిర్వచితమైతే HAVE_STRUCT_STATFS_F_FLAGS
	గమ్యం->f_flag = from->f_flags;
#లేకపోతే
	గమ్యం->f_flag = 0;
#అయితే_ముగింపు
	గమ్యం->f_namemax = MNAMELEN;
}
#అయితే_ముగింపు

# ifndef HAVE_STATVFS
పూర్ణాంకం statvfs(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం statvfs *buf)
{
#  ఒకవేళ defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	నిర్మాణం statfs fs;

	memset(&fs, 0, పరిమాణం(fs));
	ఒకవేళ (statfs(మార్గం, &fs) == -1)
		తిరిగి -1;
	copy_statfs_గమ్యం_statvfs(buf, &fs);
	తిరిగి 0;
#  లేకపోతే
	errno = ENOSYS;
	తిరిగి -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
పూర్ణాంకం fstatvfs(పూర్ణాంకం fd, నిర్మాణం statvfs *buf)
{
#  ఒకవేళ defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	నిర్మాణం statfs fs;

	memset(&fs, 0, పరిమాణం(fs));
	ఒకవేళ (fstatfs(fd, &fs) == -1)
		తిరిగి -1;
	copy_statfs_గమ్యం_statvfs(buf, &fs);
	తిరిగి 0;
#  లేకపోతే
	errno = ENOSYS;
	తిరిగి -1;
#  endif
}
# endif

#అయితే_ముగింపు
