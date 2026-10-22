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

#اگر_تعریف_شده HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#پایان_اگر

#ضمن <errno.h>

#اگر_تعریف_نشده MNAMELEN
# define MNAMELEN 32
#پایان_اگر

#اگر_تعریف_شده HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#پایان_اگر

#اگر_تعریف_شده HAVE_STRUCT_STATFS
ساكن فراغ
copy_statfs_مقصد_statvfs(بنية statvfs *مقصد, بنية statfs *from)
{
	مقصد->f_bsize = from->f_bsize;
	مقصد->f_frsize = from->f_bsize;	/* no exact equivalent */
	مقصد->f_بلوکها = from->f_بلوکها;
	مقصد->f_bfree = from->f_bfree;
	مقصد->f_bavail = from->f_bavail;
	مقصد->f_files = from->f_files;
	مقصد->f_ffree = from->f_ffree;
	مقصد->f_favail = from->f_ffree;	/* no exact equivalent */
	مقصد->f_fsid = 0;			/* XXX fix me */
#اگر_تعریف_شده HAVE_STRUCT_STATFS_F_FLAGS
	مقصد->f_flag = from->f_flags;
#وإلا
	مقصد->f_flag = 0;
#پایان_اگر
	مقصد->f_namemax = MNAMELEN;
}
#پایان_اگر

# ifndef HAVE_STATVFS
صحيح statvfs(ثابت حرف *مسیر, بنية statvfs *buf)
{
#  إذا defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	بنية statfs fs;

	memset(&fs, 0, حجم(fs));
	إذا (statfs(مسیر, &fs) == -1)
		أرجع -1;
	copy_statfs_مقصد_statvfs(buf, &fs);
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
	copy_statfs_مقصد_statvfs(buf, &fs);
	أرجع 0;
#  وإلا
	errno = ENOSYS;
	أرجع -1;
#  endif
}
# endif

#پایان_اگر
