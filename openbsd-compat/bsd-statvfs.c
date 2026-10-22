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

#جے_تعریف_شدہ HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#جے_انت

#ضمن <errno.h>

#جے_بنا_تعریف MNAMELEN
# define MNAMELEN 32
#جے_انت

#جے_تعریف_شدہ HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#جے_انت

#جے_تعریف_شدہ HAVE_STRUCT_STATFS
ساكن فراغ
copy_statfs_منزل_statvfs(بنية statvfs *منزل, بنية statfs *from)
{
	منزل->f_bsize = from->f_bsize;
	منزل->f_frsize = from->f_bsize;	/* no exact equivalent */
	منزل->f_بلاکاں = from->f_بلاکاں;
	منزل->f_bfree = from->f_bfree;
	منزل->f_bavail = from->f_bavail;
	منزل->f_files = from->f_files;
	منزل->f_ffree = from->f_ffree;
	منزل->f_favail = from->f_ffree;	/* no exact equivalent */
	منزل->f_fsid = 0;			/* XXX fix me */
#جے_تعریف_شدہ HAVE_STRUCT_STATFS_F_FLAGS
	منزل->f_flag = from->f_flags;
#وإلا
	منزل->f_flag = 0;
#جے_انت
	منزل->f_namemax = MNAMELEN;
}
#جے_انت

# ifndef HAVE_STATVFS
صحيح statvfs(ثابت حرف *رستہ, بنية statvfs *buf)
{
#  إذا defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	بنية statfs fs;

	memset(&fs, 0, حجم(fs));
	إذا (statfs(رستہ, &fs) == -1)
		أرجع -1;
	copy_statfs_منزل_statvfs(buf, &fs);
	أرجع 0;
#  وإلا
	errno = ENOSYS;
	أرجع -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
صحيح fstatvfs(صحيح fd, بنية statvfs *buf)
{
#  إذا defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	بنية statfs fs;

	memset(&fs, 0, حجم(fs));
	إذا (fstatfs(fd, &fs) == -1)
		أرجع -1;
	copy_statfs_منزل_statvfs(buf, &fs);
	أرجع 0;
#  وإلا
	errno = ENOSYS;
	أرجع -1;
#  endif
}
# endif

#جے_انت
