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

#اگر_تعریف_شدہ HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#اگر_ختم

#شامل <errno.h>

#اگر_غیر_تعریف_شدہ MNAMELEN
# define MNAMELEN 32
#اگر_ختم

#اگر_تعریف_شدہ HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#اگر_ختم

#اگر_تعریف_شدہ HAVE_STRUCT_STATFS
ساکن خالی
copy_statfs_مقصد_statvfs(ساخت statvfs *مقصد, ساخت statfs *from)
{
	مقصد->f_bsize = from->f_bsize;
	مقصد->f_frsize = from->f_bsize;	/* no exact equivalent */
	مقصد->f_بلاکیں = from->f_بلاکیں;
	مقصد->f_bfree = from->f_bfree;
	مقصد->f_bavail = from->f_bavail;
	مقصد->f_files = from->f_files;
	مقصد->f_ffree = from->f_ffree;
	مقصد->f_favail = from->f_ffree;	/* no exact equivalent */
	مقصد->f_fsid = 0;			/* XXX fix me */
#اگر_تعریف_شدہ HAVE_STRUCT_STATFS_F_FLAGS
	مقصد->f_flag = from->f_flags;
#ورنہ
	مقصد->f_flag = 0;
#اگر_ختم
	مقصد->f_namemax = MNAMELEN;
}
#اگر_ختم

# ifndef HAVE_STATVFS
صحیح statvfs(ثابت حرف *راستہ, ساخت statvfs *buf)
{
#  اگر defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	ساخت statfs fs;

	memset(&fs, 0, حجم(fs));
	اگر (statfs(راستہ, &fs) == -1)
		واپس -1;
	copy_statfs_مقصد_statvfs(buf, &fs);
	واپس 0;
#  ورنہ
	errno = ENOSYS;
	واپس -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
صحیح fstatvfs(صحیح fd, ساخت statvfs *buf)
{
#  اگر defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	ساخت statfs fs;

	memset(&fs, 0, حجم(fs));
	اگر (fstatfs(fd, &fs) == -1)
		واپس -1;
	copy_statfs_مقصد_statvfs(buf, &fs);
	واپس 0;
#  ورنہ
	errno = ENOSYS;
	واپس -1;
#  endif
}
# endif

#اگر_ختم
