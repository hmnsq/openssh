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

#समावेश "includes.h"

#अगर !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#अगर_घोषित HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#पूर्ण_अगर

#समावेश <errno.h>

#अगर_अघोषित MNAMELEN
# define MNAMELEN 32
#पूर्ण_अगर

#अगर_घोषित HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#पूर्ण_अगर

#अगर_घोषित HAVE_STRUCT_STATFS
अटल व्योम
copy_statfs_to_statvfs(काष्ठा statvfs *to, काष्ठा statfs *from)
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
#अगर_घोषित HAVE_STRUCT_STATFS_F_FLAGS
	to->f_flag = from->f_flags;
#अन्यथा
	to->f_flag = 0;
#पूर्ण_अगर
	to->f_namemax = MNAMELEN;
}
#पूर्ण_अगर

# ifndef HAVE_STATVFS
पूर्णांक statvfs(स्थिर अक्षर *path, काष्ठा statvfs *buf)
{
#  अगर defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	काष्ठा statfs fs;

	स_रखो(&fs, 0, माप(fs));
	अगर (statfs(path, &fs) == -1)
		वापस -1;
	copy_statfs_to_statvfs(buf, &fs);
	वापस 0;
#  अन्यथा
	त्रुटि_सं = ENOSYS;
	वापस -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
पूर्णांक fstatvfs(पूर्णांक fd, काष्ठा statvfs *buf)
{
#  अगर defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	काष्ठा statfs fs;

	स_रखो(&fs, 0, माप(fs));
	अगर (fstatfs(fd, &fs) == -1)
		वापस -1;
	copy_statfs_to_statvfs(buf, &fs);
	वापस 0;
#  अन्यथा
	त्रुटि_सं = ENOSYS;
	वापस -1;
#  endif
}
# endif

#पूर्ण_अगर
