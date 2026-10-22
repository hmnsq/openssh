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

#अन्तर्भाव "includes.h"

#यदि !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#यदि_परिभाषितम् HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#यदि_अन्तः

#अन्तर्भाव <errno.h>

#यदि_अपरिभाषितम् MNAMELEN
# define MNAMELEN 32
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#यदि_अन्तः

#यदि_परिभाषितम् HAVE_STRUCT_STATFS
स्थिर शून्य
copy_statfs_गन्तव्यम्_statvfs(संरचना statvfs *गन्तव्यम्, संरचना statfs *from)
{
	गन्तव्यम्->f_bsize = from->f_bsize;
	गन्तव्यम्->f_frsize = from->f_bsize;	/* no exact equivalent */
	गन्तव्यम्->f_खण्डानि = from->f_खण्डानि;
	गन्तव्यम्->f_bfree = from->f_bfree;
	गन्तव्यम्->f_bavail = from->f_bavail;
	गन्तव्यम्->f_files = from->f_files;
	गन्तव्यम्->f_ffree = from->f_ffree;
	गन्तव्यम्->f_favail = from->f_ffree;	/* no exact equivalent */
	गन्तव्यम्->f_fsid = 0;			/* XXX fix me */
#यदि_परिभाषितम् HAVE_STRUCT_STATFS_F_FLAGS
	गन्तव्यम्->f_flag = from->f_flags;
#अन्यथा
	गन्तव्यम्->f_flag = 0;
#यदि_अन्तः
	गन्तव्यम्->f_namemax = MNAMELEN;
}
#यदि_अन्तः

# ifndef HAVE_STATVFS
पूर्णाङ्क statvfs(ध्रुव वर्ण *मार्गः, संरचना statvfs *buf)
{
#  यदि defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	संरचना statfs fs;

	स्मृतिं_पूरय(&fs, 0, परिमाण(fs));
	यदि (statfs(मार्गः, &fs) == -1)
		प्रत्यागम -1;
	copy_statfs_गन्तव्यम्_statvfs(buf, &fs);
	प्रत्यागम 0;
#  अन्यथा
	errno = ENOSYS;
	प्रत्यागम -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
पूर्णाङ्क fstatvfs(पूर्णाङ्क fd, संरचना statvfs *buf)
{
#  यदि defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	संरचना statfs fs;

	स्मृतिं_पूरय(&fs, 0, परिमाण(fs));
	यदि (fstatfs(fd, &fs) == -1)
		प्रत्यागम -1;
	copy_statfs_गन्तव्यम्_statvfs(buf, &fs);
	प्रत्यागम 0;
#  अन्यथा
	errno = ENOSYS;
	प्रत्यागम -1;
#  endif
}
# endif

#यदि_अन्तः
