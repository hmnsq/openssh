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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <errno.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MNAMELEN
# define MNAMELEN 32
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_STATFS
ಸ್ಥಿರ ಶೂನ್ಯ
copy_statfs_ಗಮ್ಯ_statvfs(ರಚನೆ statvfs *ಗಮ್ಯ, ರಚನೆ statfs *from)
{
	ಗಮ್ಯ->f_bsize = from->f_bsize;
	ಗಮ್ಯ->f_frsize = from->f_bsize;	/* no exact equivalent */
	ಗಮ್ಯ->f_ಖಂಡಗಳು = from->f_ಖಂಡಗಳು;
	ಗಮ್ಯ->f_bfree = from->f_bfree;
	ಗಮ್ಯ->f_bavail = from->f_bavail;
	ಗಮ್ಯ->f_files = from->f_files;
	ಗಮ್ಯ->f_ffree = from->f_ffree;
	ಗಮ್ಯ->f_favail = from->f_ffree;	/* no exact equivalent */
	ಗಮ್ಯ->f_fsid = 0;			/* XXX fix me */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_STATFS_F_FLAGS
	ಗಮ್ಯ->f_flag = from->f_flags;
#ಇಲ್ಲದಿದ್ದರೆ
	ಗಮ್ಯ->f_flag = 0;
#ಆದರೆ_ಅಂತ್ಯ
	ಗಮ್ಯ->f_namemax = MNAMELEN;
}
#ಆದರೆ_ಅಂತ್ಯ

# ifndef HAVE_STATVFS
ಪೂರ್ಣಾಂಕ statvfs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ statvfs *buf)
{
#  ಆದರೆ defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	ರಚನೆ statfs fs;

	memset(&fs, 0, ಗಾತ್ರ(fs));
	ಆದರೆ (statfs(ಮಾರ್ಗ, &fs) == -1)
		ಹಿಂತಿರುಗಿ -1;
	copy_statfs_ಗಮ್ಯ_statvfs(buf, &fs);
	ಹಿಂತಿರುಗಿ 0;
#  ಇಲ್ಲದಿದ್ದರೆ
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
ಪೂರ್ಣಾಂಕ fstatvfs(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ statvfs *buf)
{
#  ಆದರೆ defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	ರಚನೆ statfs fs;

	memset(&fs, 0, ಗಾತ್ರ(fs));
	ಆದರೆ (fstatfs(fd, &fs) == -1)
		ಹಿಂತಿರುಗಿ -1;
	copy_statfs_ಗಮ್ಯ_statvfs(buf, &fs);
	ಹಿಂತಿರುಗಿ 0;
#  ಇಲ್ಲದಿದ್ದರೆ
	errno = ENOSYS;
	ಹಿಂತಿರುಗಿ -1;
#  endif
}
# endif

#ಆದರೆ_ಅಂತ್ಯ
