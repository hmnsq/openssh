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

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ MNAMELEN
# define MNAMELEN 32
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_STATFS
ਸਥਿਰ ਖਾਲੀ
copy_statfs_ਮੰਜ਼ਿਲ_statvfs(ਬਣਤਰ statvfs *ਮੰਜ਼ਿਲ, ਬਣਤਰ statfs *from)
{
	ਮੰਜ਼ਿਲ->f_bsize = from->f_bsize;
	ਮੰਜ਼ਿਲ->f_frsize = from->f_bsize;	/* no exact equivalent */
	ਮੰਜ਼ਿਲ->f_ਖੰਡਾਂ = from->f_ਖੰਡਾਂ;
	ਮੰਜ਼ਿਲ->f_bfree = from->f_bfree;
	ਮੰਜ਼ਿਲ->f_bavail = from->f_bavail;
	ਮੰਜ਼ਿਲ->f_files = from->f_files;
	ਮੰਜ਼ਿਲ->f_ffree = from->f_ffree;
	ਮੰਜ਼ਿਲ->f_favail = from->f_ffree;	/* no exact equivalent */
	ਮੰਜ਼ਿਲ->f_fsid = 0;			/* XXX fix me */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_STATFS_F_FLAGS
	ਮੰਜ਼ਿਲ->f_flag = from->f_flags;
#ਨਹੀਂਤਾਂ
	ਮੰਜ਼ਿਲ->f_flag = 0;
#ਜੇ_ਅੰਤ
	ਮੰਜ਼ਿਲ->f_namemax = MNAMELEN;
}
#ਜੇ_ਅੰਤ

# ifndef HAVE_STATVFS
ਪੂਰਨ statvfs(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ statvfs *buf)
{
#  ਜੇ defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	ਬਣਤਰ statfs fs;

	memset(&fs, 0, ਆਕਾਰ(fs));
	ਜੇ (statfs(ਰਸਤਾ, &fs) == -1)
		ਵਾਪਸ -1;
	copy_statfs_ਮੰਜ਼ਿਲ_statvfs(buf, &fs);
	ਵਾਪਸ 0;
#  ਨਹੀਂਤਾਂ
	errno = ENOSYS;
	ਵਾਪਸ -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
ਪੂਰਨ fstatvfs(ਪੂਰਨ fd, ਬਣਤਰ statvfs *buf)
{
#  ਜੇ defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	ਬਣਤਰ statfs fs;

	memset(&fs, 0, ਆਕਾਰ(fs));
	ਜੇ (fstatfs(fd, &fs) == -1)
		ਵਾਪਸ -1;
	copy_statfs_ਮੰਜ਼ਿਲ_statvfs(buf, &fs);
	ਵਾਪਸ 0;
#  ਨਹੀਂਤਾਂ
	errno = ENOSYS;
	ਵਾਪਸ -1;
#  endif
}
# endif

#ਜੇ_ਅੰਤ
