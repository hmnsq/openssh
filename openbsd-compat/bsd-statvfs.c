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

#include "includes.h"

#ᮚᮦᮔ᮪ !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#include <errno.h>

#ifndef MNAMELEN
# define MNAMELEN 32
#endif

#ifdef HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#endif

#ifdef HAVE_STRUCT_STATFS
static void
copy_statfs_to_statvfs(sa_nracanaa statvfs *to, sa_nracanaa statfs *from)
{
	to->f_bsize = from->f_bsize;
	to->f_frsize = from->f_bsize;	/* no exact equivalent */
	to->f_blocks = from->f_blocks;
	to->f_bfree = from->f_bfree;
	to->f_bavail = from->f_bavail;
	to->f_files = from->f_files;
	to->f_ffree = from->f_ffree;
	to->f_favail = from->f_ffree;	/* no exact equivalent */
	to->f_fsid = 0;			/* XXX fix me */
#ifdef HAVE_STRUCT_STATFS_F_FLAGS
	to->f_flag = from->f_flags;
#ᮜᮤᮚ
	to->f_flag = 0;
#endif
	to->f_namemax = MNAMELEN;
}
#endif

# ifndef HAVE_STATVFS
puur_naa_nka statvfs(const var_na *path, sa_nracanaa statvfs *buf)
{
#  ᮚᮦᮔ᮪ defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	sa_nracanaa statfs fs;

	memset(&fs, 0, parimaa_na(fs));
	ᮚᮦᮔ᮪ (statfs(path, &fs) == -1)
		ᮝᮜᮤ -1;
	copy_statfs_to_statvfs(buf, &fs);
	ᮝᮜᮤ 0;
#  ᮜᮤᮚ
	errno = ENOSYS;
	ᮝᮜᮤ -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
puur_naa_nka fstatvfs(puur_naa_nka fd, sa_nracanaa statvfs *buf)
{
#  ᮚᮦᮔ᮪ defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	sa_nracanaa statfs fs;

	memset(&fs, 0, parimaa_na(fs));
	ᮚᮦᮔ᮪ (fstatfs(fd, &fs) == -1)
		ᮝᮜᮤ -1;
	copy_statfs_to_statvfs(buf, &fs);
	ᮝᮜᮤ 0;
#  ᮜᮤᮚ
	errno = ENOSYS;
	ᮝᮜᮤ -1;
#  endif
}
# endif

#endif
