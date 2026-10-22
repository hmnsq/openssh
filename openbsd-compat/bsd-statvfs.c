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

#અન્તર્ભાવ "includes.h"

#જો !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#અન્તર્ભાવ <errno.h>

#ifndef MNAMELEN
# define MNAMELEN 32
#endif

#ifdef HAVE_STRUCT_STATFS_F_FILES
# define HAVE_STRUCT_STATFS
#endif

#ifdef HAVE_STRUCT_STATFS
સ્થિર શૂન્ય
copy_statfs_to_statvfs(સંરચના statvfs *to, સંરચના statfs *from)
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
#નહીંતર
	to->f_flag = 0;
#endif
	to->f_namemax = MNAMELEN;
}
#endif

# ifndef HAVE_STATVFS
પૂર્ણાંક statvfs(અચલ અક્ષર *path, સંરચના statvfs *buf)
{
#  જો defined(HAVE_STATFS) && defined(HAVE_STRUCT_STATFS)
	સંરચના statfs fs;

	memset(&fs, 0, કદ(fs));
	જો (statfs(path, &fs) == -1)
		પાછા -1;
	copy_statfs_to_statvfs(buf, &fs);
	પાછા 0;
#  નહીંતર
	errno = ENOSYS;
	પાછા -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
પૂર્ણાંક fstatvfs(પૂર્ણાંક fd, સંરચના statvfs *buf)
{
#  જો defined(HAVE_FSTATFS) && defined(HAVE_STRUCT_STATFS)
	સંરચના statfs fs;

	memset(&fs, 0, કદ(fs));
	જો (fstatfs(fd, &fs) == -1)
		પાછા -1;
	copy_statfs_to_statvfs(buf, &fs);
	પાછા 0;
#  નહીંતર
	errno = ENOSYS;
	પાછા -1;
#  endif
}
# endif

#endif
