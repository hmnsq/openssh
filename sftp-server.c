/* $OpenBSD: sftp-server.c,v 1.156 2026/07/01 00:52:23 dtucker Exp $ */
/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/resource.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/statvfs.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"

#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"

ಅಕ್ಷರ *sftp_realpath(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_MAX_READ_ಉದ್ದಳತೆ (SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ - 1024)

/* Our verbosity */
ಸ್ಥಿರ LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ಸ್ಥಿರ ರಚನೆ passwd *pw = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *client_addr = ಖಾಲಿ;

/* input and output queue */
ರಚನೆ sshbuf *iqueue;
ರಚನೆ sshbuf *oqueue;

/* Version of client */
ಸ್ಥಿರ u_int ಆವೃತ್ತಿ;

/* SSH2_FXP_INIT received */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ init_ಮುಗಿದ;

/* Disable writes */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ readonly;

/* Requests that are allowed/denied */
ಸ್ಥಿರ ಅಕ್ಷರ *request_allowlist, *request_denylist;

/* portable attributes, etc. */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Stat Stat;

ರಚನೆ Stat {
	ಅಕ್ಷರ *name;
	ಅಕ್ಷರ *long_name;
	Attrib attrib;
};

/* Packet handlers */
ಸ್ಥಿರ ಶೂನ್ಯ process_open(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_close(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_read(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_write(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_stat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_lstat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_fstat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_setstat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_fsetstat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_opendir(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_readdir(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_remove(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_mkdir(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_rmdir(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_realpath(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_rename(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_readlink(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_symlink(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_posix_rename(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_statvfs(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_fstatvfs(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_hardlink(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_fsync(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_lsetstat(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_limits(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_expand(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_copy_ದತ್ತಾಂಶ(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_home_directory(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_get_users_groups_by_id(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended(uint32_t id);

ರಚನೆ sftp_handler {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;	/* user-visible name for fine-grained perms */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	ಶೂನ್ಯ (*handler)(uint32_t);
	ಪೂರ್ಣಾಂಕ does_write;		/* if nonzero, banned for readonly mode */
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ಖಾಲಿ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ಖಾಲಿ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ಖಾಲಿ, SSH2_FXP_READ, process_read, 0 },
	{ "write", ಖಾಲಿ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ಖಾಲಿ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ಖಾಲಿ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ಖಾಲಿ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ಖಾಲಿ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ಖಾಲಿ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ಖಾಲಿ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ಖಾಲಿ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ಖಾಲಿ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ಖಾಲಿ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ಖಾಲಿ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ಖಾಲಿ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ಖಾಲಿ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ಖಾಲಿ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ಖಾಲಿ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ಖಾಲಿ, ಖಾಲಿ, 0, ಖಾಲಿ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler extended_handlers[] = {
	{ "posix-rename", "posix-rename@openssh.com", 0,
	    process_extended_posix_rename, 1 },
	{ "statvfs", "statvfs@openssh.com", 0, process_extended_statvfs, 0 },
	{ "fstatvfs", "fstatvfs@openssh.com", 0, process_extended_fstatvfs, 0 },
	{ "hardlink", "hardlink@openssh.com", 0, process_extended_hardlink, 1 },
	{ "fsync", "fsync@openssh.com", 0, process_extended_fsync, 1 },
	{ "lsetstat", "lsetstat@openssh.com", 0, process_extended_lsetstat, 1 },
	{ "limits", "limits@openssh.com", 0, process_extended_limits, 0 },
	{ "expand-path", "expand-path@openssh.com", 0,
	    process_extended_expand, 0 },
	{ "copy-data", "copy-data", 0, process_extended_copy_ದತ್ತಾಂಶ, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ ಖಾಲಿ, ಖಾಲಿ, 0, ಖಾಲಿ, 0 }
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler *
extended_handler_byname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; extended_handlers[i].handler != ಖಾಲಿ; i++) {
		ಆದರೆ (strcmp(name, extended_handlers[i].ext_name) == 0)
			ಹಿಂತಿರುಗಿ &extended_handlers[i];
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
request_permitted(ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler *h)
{
	ಅಕ್ಷರ *ಫಲಿತಾಂಶ;

	ಆದರೆ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (request_denylist != ಖಾಲಿ &&
	    ((ಫಲಿತಾಂಶ = ಹೊಂದಿಕೆ_list(h->name, request_denylist, ಖಾಲಿ))) != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ);
		verbose("Refusing denylisted %s request", h->name);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (request_allowlist != ಖಾಲಿ &&
	    ((ಫಲಿತಾಂಶ = ಹೊಂದಿಕೆ_list(h->name, request_allowlist, ಖಾಲಿ))) != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ);
		debug2("Permitting allowlisted %s request", h->name);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಆದರೆ (request_allowlist != ಖಾಲಿ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
errno_ಗಮ್ಯ_portable(ಪೂರ್ಣಾಂಕ unixerrno)
{
	ಪೂರ್ಣಾಂಕ ret = 0;

	ಆಯ್ಕೆ (unixerrno) {
	ಸ್ಥಿತಿ 0:
		ret = SSH2_FX_OK;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ENOENT:
	ಸ್ಥಿತಿ ENOTDIR:
	ಸ್ಥಿತಿ EBADF:
	ಸ್ಥಿತಿ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ EPERM:
	ಸ್ಥಿತಿ EACCES:
	ಸ್ಥಿತಿ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ENAMETOOLONG:
	ಸ್ಥಿತಿ EINVAL:
		ret = SSH2_FX_BAD_ಸಂದೇಶ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ret = SSH2_FX_FAILURE;
		ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
flags_from_portable(ಪೂರ್ಣಾಂಕ pflags)
{
	ಪೂರ್ಣಾಂಕ flags = 0;

	ಆದರೆ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	ಆದರೆ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	ಆದರೆ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	ಆದರೆ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	ಆದರೆ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	ಹಿಂತಿರುಗಿ flags;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
string_from_portable(ಪೂರ್ಣಾಂಕ pflags)
{
	ಸ್ಥಿರ ಅಕ್ಷರ ret[128];

	*ret = '\0';

#ವ್ಯಾಖ್ಯಾನಿಸು PAPPEND(str)	{				\
		ಆದರೆ (*ret != '\0')			\
			strlcat(ret, ",", ಗಾತ್ರ(ret));	\
		strlcat(ret, str, ಗಾತ್ರ(ret));		\
	}

	ಆದರೆ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	ಆದರೆ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	ಆದರೆ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	ಆದರೆ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	ಆದರೆ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	ಆದರೆ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	ಹಿಂತಿರುಗಿ ret;
}

/* handle handles */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Handle Handle;
ರಚನೆ Handle {
	ಪೂರ್ಣಾಂಕ use;
	DIR *dirp;
	ಪೂರ್ಣಾಂಕ fd;
	ಪೂರ್ಣಾಂಕ flags;
	ಅಕ್ಷರ *name;
	uint64_t ಬೈಟುಗಳು_read, ಬೈಟುಗಳು_write;
	ಪೂರ್ಣಾಂಕ ಮುಂದಿನ_ಬಳಸದ;
};

ಎಣಿಕೆ {
	HANDLE_ಬಳಸದ,
	HANDLE_DIR,
	HANDLE_FILE
};

ಸ್ಥಿರ Handle *handles = ಖಾಲಿ;
ಸ್ಥಿರ u_int ಅಂಕೆ_handles = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಮೊದಲ_ಬಳಸದ_handle = -1;

ಸ್ಥಿರ ಶೂನ್ಯ handle_ಬಳಸದ(ಪೂರ್ಣಾಂಕ i)
{
	handles[i].use = HANDLE_ಬಳಸದ;
	handles[i].ಮುಂದಿನ_ಬಳಸದ = ಮೊದಲ_ಬಳಸದ_handle;
	ಮೊದಲ_ಬಳಸದ_handle = i;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_new(ಪೂರ್ಣಾಂಕ use, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ flags, DIR *dirp)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (ಮೊದಲ_ಬಳಸದ_handle == -1) {
		ಆದರೆ (ಅಂಕೆ_handles + 1 <= ಅಂಕೆ_handles)
			ಹಿಂತಿರುಗಿ -1;
		ಅಂಕೆ_handles++;
		handles = xreallocarray(handles, ಅಂಕೆ_handles, ಗಾತ್ರ(Handle));
		handle_ಬಳಸದ(ಅಂಕೆ_handles - 1);
	}

	i = ಮೊದಲ_ಬಳಸದ_handle;
	ಮೊದಲ_ಬಳಸದ_handle = handles[i].ಮುಂದಿನ_ಬಳಸದ;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].ಬೈಟುಗಳು_read = handles[i].ಬೈಟುಗಳು_write = 0;

	ಹಿಂತಿರುಗಿ i;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_is_ok(ಪೂರ್ಣಾಂಕ i, ಪೂರ್ಣಾಂಕ type)
{
	ಹಿಂತಿರುಗಿ i >= 0 && (u_int)i < ಅಂಕೆ_handles && handles[i].use == type;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_ಗಮ್ಯ_string(ಪೂರ್ಣಾಂಕ handle, u_char **stringp, ಪೂರ್ಣಾಂಕ *hlenp)
{
	ಆದರೆ (stringp == ಖಾಲಿ || hlenp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	*stringp = xmalloc(ಗಾತ್ರ(int32_t));
	put_u32(*stringp, handle);
	*hlenp = ಗಾತ್ರ(int32_t);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_from_string(ಸ್ಥಿರಾಂಕ u_char *handle, u_int hlen)
{
	ಪೂರ್ಣಾಂಕ val;

	ಆದರೆ (hlen != ಗಾತ್ರ(int32_t))
		ಹಿಂತಿರುಗಿ -1;
	val = get_u32(handle);
	ಆದರೆ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		ಹಿಂತಿರುಗಿ val;
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
handle_ಗಮ್ಯ_name(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		ಹಿಂತಿರುಗಿ handles[handle].name;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ DIR *
handle_ಗಮ್ಯ_dir(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_DIR))
		ಹಿಂತಿರುಗಿ handles[handle].dirp;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_ಗಮ್ಯ_fd(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE))
		ಹಿಂತಿರುಗಿ handles[handle].fd;
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_ಗಮ್ಯ_flags(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE))
		ಹಿಂತಿರುಗಿ handles[handle].flags;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_update_read(ಪೂರ್ಣಾಂಕ handle, ssize_t ಬೈಟುಗಳು)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE) && ಬೈಟುಗಳು > 0)
		handles[handle].ಬೈಟುಗಳು_read += ಬೈಟುಗಳು;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_update_write(ಪೂರ್ಣಾಂಕ handle, ssize_t ಬೈಟುಗಳು)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE) && ಬೈಟುಗಳು > 0)
		handles[handle].ಬೈಟುಗಳು_write += ಬೈಟುಗಳು;
}

ಸ್ಥಿರ uint64_t
handle_ಬೈಟುಗಳು_read(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE))
		ಹಿಂತಿರುಗಿ (handles[handle].ಬೈಟುಗಳು_read);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ uint64_t
handle_ಬೈಟುಗಳು_write(ಪೂರ್ಣಾಂಕ handle)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE))
		ಹಿಂತಿರುಗಿ (handles[handle].ಬೈಟುಗಳು_write);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_close(ಪೂರ್ಣಾಂಕ handle)
{
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		ಬಿಡುಗಡೆ(handles[handle].name);
		handle_ಬಳಸದ(handle);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		ಬಿಡುಗಡೆ(handles[handle].name);
		handle_ಬಳಸದ(handle);
	} ಇಲ್ಲದಿದ್ದರೆ {
		errno = ENOENT;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_log_close(ಪೂರ್ಣಾಂಕ handle, ಅಕ್ಷರ *emsg)
{
	ಆದರೆ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ಖಾಲಿ ? "" : emsg, emsg == ಖಾಲಿ ? "" : " ",
		    handle_ಗಮ್ಯ_name(handle),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)handle_ಬೈಟುಗಳು_read(handle),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)handle_ಬೈಟುಗಳು_write(handle));
	} ಇಲ್ಲದಿದ್ದರೆ {
		logit("%s%sclosedir \"%s\"",
		    emsg == ಖಾಲಿ ? "" : emsg, emsg == ಖಾಲಿ ? "" : " ",
		    handle_ಗಮ್ಯ_name(handle));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_log_exit(ಶೂನ್ಯ)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_handles; i++)
		ಆದರೆ (handles[i].use != HANDLE_ಬಳಸದ)
			handle_log_close(i, "forced");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_handle(ರಚನೆ sshbuf *ಸರತಿ, ಪೂರ್ಣಾಂಕ *hp)
{
	u_char *handle;
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t hlen;

	*hp = -1;
	ಆದರೆ ((r = sshbuf_get_string(ಸರತಿ, &handle, &hlen)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	ಬಿಡುಗಡೆ(handle);
	ಹಿಂತಿರುಗಿ 0;
}

/* send replies */

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ಸ್ಥಿತಿ_ಗಮ್ಯ_ಸಂದೇಶ(uint32_t ಸ್ಥಿತಿ_2)
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ ಸ್ಥಿತಿ_messages[] = {
		"Success",			/* SSH_FX_OK */
		"End of file",			/* SSH_FX_EOF */
		"No such file",			/* SSH_FX_NO_SUCH_FILE */
		"Permission denied",		/* SSH_FX_PERMISSION_DENIED */
		"Failure",			/* SSH_FX_FAILURE */
		"Bad message",			/* SSH_FX_BAD_MESSAGE */
		"No connection",		/* SSH_FX_NO_CONNECTION */
		"Connection lost",		/* SSH_FX_CONNECTION_LOST */
		"Operation unsupported",	/* SSH_FX_OP_UNSUPPORTED */
		"Unknown error"			/* Others */
	};
	ಹಿಂತಿರುಗಿ (ಸ್ಥಿತಿ_messages[MINIMUM(ಸ್ಥಿತಿ_2,SSH2_FX_MAX)]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸ್ಥಿತಿ_errmsg(uint32_t id, uint32_t ಸ್ಥಿತಿ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errmsg)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	debug3("request %u: sent status %u", id, ಸ್ಥಿತಿ_2);
	ಆದರೆ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (ಸ್ಥಿತಿ_2 != SSH2_FX_OK && ಸ್ಥಿತಿ_2 != SSH2_FX_EOF))
		logit("sent status %s", ಸ್ಥಿತಿ_ಗಮ್ಯ_ಸಂದೇಶ(ಸ್ಥಿತಿ_2));
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_ಸ್ಥಿತಿ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, ಸ್ಥಿತಿ_2)) != 0)
		fatal_fr(r, "compose");
	ಆದರೆ (ಆವೃತ್ತಿ >= 3) {
		ಆದರೆ ((r = sshbuf_put_cstring(ಸಂದೇಶ, errmsg == ಖಾಲಿ ?
		    ಸ್ಥಿತಿ_ಗಮ್ಯ_ಸಂದೇಶ(ಸ್ಥಿತಿ_2) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸ್ಥಿತಿ(uint32_t id, uint32_t ಸ್ಥಿತಿ_2)
{
	send_ಸ್ಥಿತಿ_errmsg(id, ಸ್ಥಿತಿ_2, ಖಾಲಿ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ದತ್ತಾಂಶ_or_handle(ಅಕ್ಷರ type, uint32_t id, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಪೂರ್ಣಾಂಕ dlen)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, ದತ್ತಾಂಶ, dlen)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ದತ್ತಾಂಶ(uint32_t id, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಪೂರ್ಣಾಂಕ dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_ದತ್ತಾಂಶ_or_handle(SSH2_FXP_ದತ್ತಾಂಶ, id, ದತ್ತಾಂಶ, dlen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_handle(uint32_t id, ಪೂರ್ಣಾಂಕ handle)
{
	u_char *string;
	ಪೂರ್ಣಾಂಕ hlen;

	handle_ಗಮ್ಯ_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_ದತ್ತಾಂಶ_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	ಬಿಡುಗಡೆ(string);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಹೆಸರುಗಳು(uint32_t id, ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2, ಸ್ಥಿರಾಂಕ Stat *stats)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ i, r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, ಎಣಿಕೆ_2)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, ಎಣಿಕೆ_2);
	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(ಸಂದೇಶ, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(ಸಂದೇಶ, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_attrib(uint32_t id, ಸ್ಥಿರಾಂಕ Attrib *a)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_statvfs(uint32_t id, ರಚನೆ statvfs *st)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	uint64_t flag;
	ಪೂರ್ಣಾಂಕ r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_ಉತ್ತರ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_ಖಂಡಗಳು)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, FSID_ಗಮ್ಯ_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, flag)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compose_extension(ರಚನೆ sshbuf *ಸಂದೇಶ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ver)
{
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler *exthnd;

	ಆದರೆ ((exthnd = extended_handler_byname(name)) == ಖಾಲಿ)
		fatal_f("internal error: no handler for %s", name);
	ಆದರೆ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((r = sshbuf_put_cstring(ಸಂದೇಶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	ಹಿಂತಿರುಗಿ 0;
}

/* parse incoming */

ಸ್ಥಿರ ಶೂನ್ಯ
process_init(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_u32(iqueue, &ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", ಆವೃತ್ತಿ);
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FILEXFER_ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(ಸಂದೇಶ, "posix-rename@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "statvfs@openssh.com", "2");
	compose_extension(ಸಂದೇಶ, "fstatvfs@openssh.com", "2");
	compose_extension(ಸಂದೇಶ, "hardlink@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "fsync@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "lsetstat@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "limits@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "expand-path@openssh.com", "1");
	compose_extension(ಸಂದೇಶ, "copy-data", "1");
	compose_extension(ಸಂದೇಶ, "home-directory", "1");
	compose_extension(ಸಂದೇಶ, "users-groups-by-id@openssh.com", "1");

	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, handle, fd, flags, ಬಹುಲಕ, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	ಬಹುಲಕ = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), ಬಹುಲಕ);
	ಆದರೆ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		ಸ್ಥಿತಿ_2 = SSH2_FX_PERMISSION_DENIED;
	} ಇಲ್ಲದಿದ್ದರೆ {
		fd = open(name, flags, ಬಹುಲಕ);
		ಆದರೆ (fd == -1) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		} ಇಲ್ಲದಿದ್ದರೆ {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ಖಾಲಿ);
			ಆದರೆ (handle < 0) {
				close(fd);
			} ಇಲ್ಲದಿದ್ದರೆ {
				send_handle(id, handle);
				ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
			}
		}
	}
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_close(uint32_t id)
{
	ಪೂರ್ಣಾಂಕ r, handle, ret, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ಖಾಲಿ);
	ret = handle_close(handle);
	ಸ್ಥಿತಿ_2 = (ret == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_read(uint32_t id)
{
	ಸ್ಥಿರ u_char *buf;
	ಸ್ಥಿರ ಗಾತ್ರ_t buflen;
	uint32_t len;
	ಪೂರ್ಣಾಂಕ r, handle, fd, ret, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	uint64_t off;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_ಗಮ್ಯ_name(handle), handle, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)off, len);
	ಆದರೆ ((fd = handle_ಗಮ್ಯ_fd(handle)) == -1)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (len > SFTP_MAX_READ_ಉದ್ದಳತೆ) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_ಉದ್ದಳತೆ);
		len = SFTP_MAX_READ_ಉದ್ದಳತೆ;
	}
	ಆದರೆ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		ಆದರೆ ((buf = realloc(buf, len)) == ಖಾಲಿ)
			fatal_f("realloc failed");
		buflen = len;
	}
	ಆದರೆ (lseek(fd, off, SEEK_SET) == -1) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("seek \"%.100s\": %s", handle_ಗಮ್ಯ_name(handle),
		    strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ret = ಪಠ(fd, buf, len)) == -1) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("read \"%.100s\": %s", handle_ಗಮ್ಯ_name(handle),
		    strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == 0) {
		ಸ್ಥಿತಿ_2 = SSH2_FX_EOF;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	send_ದತ್ತಾಂಶ(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
 ಹೊರಹೋಗು:
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_write(uint32_t id)
{
	uint64_t off;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r, handle, fd, ret, ಸ್ಥಿತಿ_2;
	u_char *ದತ್ತಾಂಶ;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &ದತ್ತಾಂಶ, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_ಗಮ್ಯ_name(handle), handle, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)off, len);
	fd = handle_ಗಮ್ಯ_fd(handle);

	ಆದರೆ (fd < 0)
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!(handle_ಗಮ್ಯ_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
			error_f("seek \"%.100s\": %s", handle_ಗಮ್ಯ_name(handle),
			    strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ {
/* XXX ATOMICIO ? */
			ret = ಲಿಖ(fd, ದತ್ತಾಂಶ, len);
			ಆದರೆ (ret == -1) {
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_ಗಮ್ಯ_name(handle), strerror(errno));
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಗಾತ್ರ_t)ret == len) {
				ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} ಇಲ್ಲದಿದ್ದರೆ {
				debug2_f("nothing at all written");
				ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
			}
		}
	}
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_do_stat(uint32_t id, ಪೂರ್ಣಾಂಕ do_lstat)
{
	Attrib a;
	ರಚನೆ stat st;
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	ಆದರೆ (r == -1) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	} ಇಲ್ಲದಿದ್ದರೆ {
		stat_ಗಮ್ಯ_attrib(&st, &a);
		send_attrib(id, &a);
		ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
	}
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_fstat(uint32_t id)
{
	Attrib a;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ fd, r, handle, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_ಗಮ್ಯ_name(handle), handle);
	fd = handle_ಗಮ್ಯ_fd(handle);
	ಆದರೆ (fd >= 0) {
		r = fstat(fd, &st);
		ಆದರೆ (r == -1) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		} ಇಲ್ಲದಿದ್ದರೆ {
			stat_ಗಮ್ಯ_attrib(&st, &a);
			send_attrib(id, &a);
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
		}
	}
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ರಚನೆ timeval *
attrib_ಗಮ್ಯ_tv(ಸ್ಥಿರಾಂಕ Attrib *a)
{
	ಸ್ಥಿರ ರಚನೆ timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	ಹಿಂತಿರುಗಿ tv;
}

ಸ್ಥಿರ ರಚನೆ timespec *
attrib_ಗಮ್ಯ_ts(ಸ್ಥಿರಾಂಕ Attrib *a)
{
	ಸ್ಥಿರ ರಚನೆ timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	ಹಿಂತಿರುಗಿ ts;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_setstat(uint32_t id)
{
	Attrib a;
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2 = SSH2_FX_OK;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ) {
		logit("set \"%s\" size %llu",
		    name, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)a.ಗಾತ್ರ_2);
		r = truncate(name, a.ಗಾತ್ರ_2);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಅಕ್ಷರ buf[64];
		time_t t = a.mtime;

		strftime(buf, ಗಾತ್ರ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_ಗಮ್ಯ_tv(&a));
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_fsetstat(uint32_t id)
{
	Attrib a;
	ಪೂರ್ಣಾಂಕ handle, fd, r;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2 = SSH2_FX_OK;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_ಗಮ್ಯ_fd(handle);
	ಆದರೆ (fd < 0)
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಅಕ್ಷರ *name = handle_ಗಮ್ಯ_name(handle);

		ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ) {
			logit("set \"%s\" size %llu",
			    name, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)a.ಗಾತ್ರ_2);
			r = ftruncate(fd, a.ಗಾತ್ರ_2);
			ಆದರೆ (r == -1)
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		}
		ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#ಇಲ್ಲದಿದ್ದರೆ
			r = chmod(name, a.perm & 07777);
#ಆದರೆ_ಅಂತ್ಯ
			ಆದರೆ (r == -1)
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		}
		ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ಅಕ್ಷರ buf[64];
			time_t t = a.mtime;

			strftime(buf, ಗಾತ್ರ(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FUTIMES
			r = futimes(fd, attrib_ಗಮ್ಯ_tv(&a));
#ಇಲ್ಲದಿದ್ದರೆ
			r = utimes(name, attrib_ಗಮ್ಯ_tv(&a));
#ಆದರೆ_ಅಂತ್ಯ
			ಆದರೆ (r == -1)
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		}
		ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#ಇಲ್ಲದಿದ್ದರೆ
			r = chown(name, a.uid, a.gid);
#ಆದರೆ_ಅಂತ್ಯ
			ಆದರೆ (r == -1)
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		}
	}
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_opendir(uint32_t id)
{
	DIR *dirp = ಖಾಲಿ;
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ r, handle, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", ಮಾರ್ಗ);
	dirp = opendir(ಮಾರ್ಗ);
	ಆದರೆ (dirp == ಖಾಲಿ) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	} ಇಲ್ಲದಿದ್ದರೆ {
		handle = handle_new(HANDLE_DIR, ಮಾರ್ಗ, 0, 0, dirp);
		ಆದರೆ (handle < 0) {
			closedir(dirp);
		} ಇಲ್ಲದಿದ್ದರೆ {
			send_handle(id, handle);
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
		}

	}
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_readdir(uint32_t id)
{
	DIR *dirp;
	ರಚನೆ dirent *dp;
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ r, handle;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_ಗಮ್ಯ_name(handle), handle);
	dirp = handle_ಗಮ್ಯ_dir(handle);
	ಮಾರ್ಗ = handle_ಗಮ್ಯ_name(handle);
	ಆದರೆ (dirp == ಖಾಲಿ || ಮಾರ್ಗ == ಖಾಲಿ) {
		send_ಸ್ಥಿತಿ(id, SSH2_FX_FAILURE);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ರಚನೆ stat st;
		ಅಕ್ಷರ *pathname;
		Stat *stats;
		ಪೂರ್ಣಾಂಕ nstats = 10, ಎಣಿಕೆ_2 = 0, i;

		stats = xcalloc(nstats, ಗಾತ್ರ(Stat));
		ಆಗ ((dp = readdir(dirp)) != ಖಾಲಿ) {
			ಆದರೆ (ಎಣಿಕೆ_2 >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, ಗಾತ್ರ(Stat));
			}
			xasprintf(&pathname, "%s%s%s", ಮಾರ್ಗ,
			    strcmp(ಮಾರ್ಗ, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			ಬಿಡುಗಡೆ(pathname);
			ಆದರೆ (r == -1)
				ಮುಂದುವರಿ;
			stat_ಗಮ್ಯ_attrib(&st, &(stats[ಎಣಿಕೆ_2].attrib));
			stats[ಎಣಿಕೆ_2].name = xstrdup(dp->d_name);
			stats[ಎಣಿಕೆ_2].long_name = ls_file(dp->d_name, &st,
			    0, 0, ಖಾಲಿ, ಖಾಲಿ);
			ಎಣಿಕೆ_2++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			ಆದರೆ (ಎಣಿಕೆ_2 == 100)
				ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ಎಣಿಕೆ_2 > 0) {
			send_ಹೆಸರುಗಳು(id, ಎಣಿಕೆ_2, stats);
			ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
				ಬಿಡುಗಡೆ(stats[i].name);
				ಬಿಡುಗಡೆ(stats[i].long_name);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			send_ಸ್ಥಿತಿ(id, SSH2_FX_EOF);
		}
		ಬಿಡುಗಡೆ(stats);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove(uint32_t id)
{
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_mkdir(uint32_t id)
{
	Attrib a;
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಬಹುಲಕ, ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	ಬಹುಲಕ = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, ಬಹುಲಕ);
	r = mkdir(name, ಬಹುಲಕ);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_rmdir(uint32_t id)
{
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_realpath(uint32_t id)
{
	ಅಕ್ಷರ resolvedname[PATH_MAX];
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (ಮಾರ್ಗ[0] == '\0') {
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಮಾರ್ಗ = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", ಮಾರ್ಗ);
	ಆದರೆ (sftp_realpath(ಮಾರ್ಗ, resolvedname) == ಖಾಲಿ) {
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
	} ಇಲ್ಲದಿದ್ದರೆ {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_ಹೆಸರುಗಳು(id, 1, &s);
	}
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_rename(uint32_t id)
{
	ಅಕ್ಷರ *oldpath, *newpath;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;
	ರಚನೆ stat sb;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &oldpath, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	ಆದರೆ (lstat(oldpath, &sb) == -1)
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		ಆದರೆ (link(oldpath, newpath) == -1) {
			ಆದರೆ (errno == EOPNOTSUPP || errno == ENOSYS
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EXDEV
			    || errno == EXDEV
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#ಆದರೆ_ಅಂತ್ಯ
			    ) {
				ರಚನೆ stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				ಆದರೆ (stat(newpath, &st) == -1) {
					ಆದರೆ (rename(oldpath, newpath) == -1)
						ಸ್ಥಿತಿ_2 =
						    errno_ಗಮ್ಯ_portable(errno);
					ಇಲ್ಲದಿದ್ದರೆ
						ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (unlink(oldpath) == -1) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} ಇಲ್ಲದಿದ್ದರೆ
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (stat(newpath, &sb) == -1) {
		ಆದರೆ (rename(oldpath, newpath) == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		ಇಲ್ಲದಿದ್ದರೆ
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
	}
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(oldpath);
	ಬಿಡುಗಡೆ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_readlink(uint32_t id)
{
	ಪೂರ್ಣಾಂಕ r, len;
	ಅಕ್ಷರ buf[PATH_MAX];
	ಅಕ್ಷರ *ಮಾರ್ಗ;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", ಮಾರ್ಗ);
	ಆದರೆ ((len = readlink(ಮಾರ್ಗ, buf, ಗಾತ್ರ(buf) - 1)) == -1)
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
	ಇಲ್ಲದಿದ್ದರೆ {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_ಹೆಸರುಗಳು(id, 1, &s);
	}
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_symlink(uint32_t id)
{
	ಅಕ್ಷರ *oldpath, *newpath;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &oldpath, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(oldpath);
	ಬಿಡುಗಡೆ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_posix_rename(uint32_t id)
{
	ಅಕ್ಷರ *oldpath, *newpath;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &oldpath, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(oldpath);
	ಬಿಡುಗಡೆ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_statvfs(uint32_t id)
{
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ರಚನೆ statvfs st;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", ಮಾರ್ಗ);

	ಆದರೆ (statvfs(ಮಾರ್ಗ, &st) != 0)
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		send_statvfs(id, &st);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_fstatvfs(uint32_t id)
{
	ಪೂರ್ಣಾಂಕ r, handle, fd;
	ರಚನೆ statvfs st;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_ಗಮ್ಯ_name(handle), handle);
	ಆದರೆ ((fd = handle_ಗಮ್ಯ_fd(handle)) < 0) {
		send_ಸ್ಥಿತಿ(id, SSH2_FX_FAILURE);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (fstatvfs(fd, &st) != 0)
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
	ಇಲ್ಲದಿದ್ದರೆ
		send_statvfs(id, &st);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_hardlink(uint32_t id)
{
	ಅಕ್ಷರ *oldpath, *newpath;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &oldpath, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(oldpath);
	ಬಿಡುಗಡೆ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_fsync(uint32_t id)
{
	ಪೂರ್ಣಾಂಕ handle, fd, r, ಸ್ಥಿತಿ_2 = SSH2_FX_OP_UNSUPPORTED;

	ಆದರೆ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_ಗಮ್ಯ_name(handle));
	ಆದರೆ ((fd = handle_ಗಮ್ಯ_fd(handle)) < 0)
		ಸ್ಥಿತಿ_2 = SSH2_FX_NO_SUCH_FILE;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		ಸ್ಥಿತಿ_2 = (r == -1) ? errno_ಗಮ್ಯ_portable(errno) : SSH2_FX_OK;
	}
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	ಅಕ್ಷರ *name;
	ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿತಿ_2 = SSH2_FX_OK;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &name, ಖಾಲಿ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ) {
		/* nonsensical for links */
		ಸ್ಥಿತಿ_2 = SSH2_FX_BAD_ಸಂದೇಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಅಕ್ಷರ buf[64];
		time_t t = a.mtime;

		strftime(buf, ಗಾತ್ರ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_ಗಮ್ಯ_ts(&a), AT_SYMLINK_NOFOLLOW);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
	ಆದರೆ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		ಆದರೆ (r == -1)
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
	}
 ಹೊರಹೋಗು:
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
	ಬಿಡುಗಡೆ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_limits(uint32_t id)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;
	uint64_t nfiles = 0;
#ಆದರೆ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ರಚನೆ rlimit rlim;
#ಆದರೆ_ಅಂತ್ಯ

	debug("request %u: limits", id);

#ಆದರೆ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ಆದರೆ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_ಉತ್ತರ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_READ_ಉದ್ದಳತೆ)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_expand(uint32_t id)
{
	ಅಕ್ಷರ cwd[PATH_MAX], resolvedname[PATH_MAX];
	ಅಕ್ಷರ *ಮಾರ್ಗ, *npath;
	ಪೂರ್ಣಾಂಕ r;
	Stat s;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &ಮಾರ್ಗ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (getcwd(cwd, ಗಾತ್ರ(cwd)) == ಖಾಲಿ) {
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug3("request %u: expand, original \"%s\"", id, ಮಾರ್ಗ);
	ಆದರೆ (ಮಾರ್ಗ[0] == '\0') {
		/* empty path */
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಮಾರ್ಗ = xstrdup(".");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*ಮಾರ್ಗ == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		ಆದರೆ (strcmp(ಮಾರ್ಗ, "~") == 0) {
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಮಾರ್ಗ = xstrdup(cwd);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಮಾರ್ಗ, "~/", 2) == 0) {
			npath = xstrdup(ಮಾರ್ಗ + 2);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			xasprintf(&ಮಾರ್ಗ, "%s/%s", cwd, npath);
			ಬಿಡುಗಡೆ(npath);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* ~user expansions */
			ಆದರೆ (tilde_expand(ಮಾರ್ಗ, pw->pw_uid, &npath) != 0) {
				send_ಸ್ಥಿತಿ_errmsg(id,
				    errno_ಗಮ್ಯ_portable(ENOENT), "no such user");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಮಾರ್ಗ = npath;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*ಮಾರ್ಗ != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಮಾರ್ಗ = npath;
	}
	verbose("expand \"%s\"", ಮಾರ್ಗ);
	ಆದರೆ (sftp_realpath(ಮಾರ್ಗ, resolvedname) == ಖಾಲಿ) {
		send_ಸ್ಥಿತಿ(id, errno_ಗಮ್ಯ_portable(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_ಹೆಸರುಗಳು(id, 1, &s);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_copy_ದತ್ತಾಂಶ(uint32_t id)
{
	u_char buf[64*1024];
	ಪೂರ್ಣಾಂಕ read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	ಪೂರ್ಣಾಂಕ r, copy_until_eof, ಸ್ಥಿತಿ_2 = SSH2_FX_OP_UNSUPPORTED;
	ಗಾತ್ರ_t ret;
	ರಚನೆ stat st_read, st_write;

	ಆದರೆ ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_ಗಮ್ಯ_name(read_handle), read_handle,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)read_off, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)read_len,
	    handle_ಗಮ್ಯ_name(write_handle), write_handle,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)write_off);

	/* For read length of 0, we read until EOF. */
	ಆದರೆ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} ಇಲ್ಲದಿದ್ದರೆ
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_ಗಮ್ಯ_fd(read_handle);
	write_fd = handle_ಗಮ್ಯ_fd(write_handle);
	ಆದರೆ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(EBADF);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fstat(read_fd, &st_read) != 0) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fstat(write_fd, &st_write) != 0) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (read_handle == write_handle ||
	    !strcmp(handle_ಗಮ್ಯ_name(read_handle), handle_ಗಮ್ಯ_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_ಗಮ್ಯ_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_ಗಮ್ಯ_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("read_seek failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((handle_ಗಮ್ಯ_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
		error_f("write_seek failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Process the request in chunks. */
	ಆಗ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(ಗಾತ್ರ(buf), read_len);
		read_len -= len;

		ret = atomicio(ಪಠ, read_fd, buf, len);
		ಆದರೆ (ret == 0 && errno == EPIPE) {
			ಸ್ಥಿತಿ_2 = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ನಿಲ್ಲಿಸು;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == 0) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		ಆದರೆ (ret != len) {
			ಸ್ಥಿತಿ_2 = errno_ಗಮ್ಯ_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ret, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)len,
			    strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		handle_update_write(write_handle, len);
	}

	ಆದರೆ (read_len == 0)
		ಸ್ಥಿತಿ_2 = SSH2_FX_OK;

 ಹೊರಹೋಗು:
	send_ಸ್ಥಿತಿ(id, ಸ್ಥಿತಿ_2);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_home_directory(uint32_t id)
{
	ಅಕ್ಷರ *username;
	ರಚನೆ passwd *user_pw;
	ಪೂರ್ಣಾಂಕ r;
	Stat s;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &username, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	ಆದರೆ (username[0] == '\0') {
		user_pw = pw;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((user_pw = getpwnam(username)) == ಖಾಲಿ) {
		send_ಸ್ಥಿತಿ(id, SSH2_FX_FAILURE);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_ಹೆಸರುಗಳು(id, 1, &s);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(username);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_get_users_groups_by_id(uint32_t id)
{
	ರಚನೆ passwd *user_pw;
	ರಚನೆ ಗುಂಪು *gr;
	ರಚನೆ sshbuf *uids, *gids, *usernames, *groupnames, *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;
	u_int n, nusers = 0, ngroups = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;

	ಆದರೆ ((usernames = sshbuf_new()) == ಖಾಲಿ ||
	    (groupnames = sshbuf_new()) == ಖಾಲಿ ||
	    (ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	ಆಗ (sshbuf_len(uids) != 0) {
		ಆದರೆ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ಖಾಲಿ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		ಆದರೆ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	ಆಗ (sshbuf_len(gids) != 0) {
		ಆದರೆ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ಖಾಲಿ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		ಆದರೆ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_ಉತ್ತರ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended(uint32_t id)
{
	ಅಕ್ಷರ *request;
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sftp_handler *exthand;

	ಆದರೆ ((r = sshbuf_get_cstring(iqueue, &request, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ ((exthand = extended_handler_byname(request)) == ಖಾಲಿ) {
		error("Unknown extended request \"%.100s\"", request);
		send_ಸ್ಥಿತಿ(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!request_permitted(exthand))
			send_ಸ್ಥಿತಿ(id, SSH2_FX_PERMISSION_DENIED);
		ಇಲ್ಲದಿದ್ದರೆ
			exthand->handler(id);
	}
	ಬಿಡುಗಡೆ(request);
}

/* stolen from ssh-agent */

ಸ್ಥಿರ ಶೂನ್ಯ
process(ಶೂನ್ಯ)
{
	u_int ಸಂದೇಶ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಪೂರ್ಣಾಂಕ i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	ಆದರೆ (buf_len < 5)
		ಹಿಂತಿರುಗಿ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ಸಂದೇಶ_len = get_u32(cp);
	ಆದರೆ (ಸಂದೇಶ_len > SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	ಆದರೆ (buf_len < ಸಂದೇಶ_len + 4)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	ಆದರೆ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH2_FXP_INIT:
		process_init();
		init_ಮುಗಿದ = 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_FXP_EXTENDED:
		ಆದರೆ (!init_ಮುಗಿದ)
			fatal("Received extended request before init");
		ಆದರೆ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆದರೆ (!init_ಮುಗಿದ)
			fatal("Received %u request before init", type);
		ಆದರೆ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		ಗಾಗಿ (i = 0; handlers[i].handler != ಖಾಲಿ; i++) {
			ಆದರೆ (type == handlers[i].type) {
				ಆದರೆ (!request_permitted(&handlers[i])) {
					send_ಸ್ಥಿತಿ(id,
					    SSH2_FX_PERMISSION_DENIED);
				} ಇಲ್ಲದಿದ್ದರೆ {
					handlers[i].handler(id);
				}
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (handlers[i].handler == ಖಾಲಿ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	ಆದರೆ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ಆದರೆ (ಸಂದೇಶ_len < consumed) {
		error("msg_len %u < consumed %u", ಸಂದೇಶ_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	ಆದರೆ (ಸಂದೇಶ_len > consumed &&
	    (r = sshbuf_consume(iqueue, ಸಂದೇಶ_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
ಶೂನ್ಯ
sftp_server_cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	ಆದರೆ (pw != ಖಾಲಿ && client_addr != ಖಾಲಿ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sftp_server_usage(ಶೂನ್ಯ)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
sftp_server_main(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ರಚನೆ passwd *user_pw)
{
	ಪೂರ್ಣಾಂಕ i, r, ಒಳ, ಹೊರಹೋಗು, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	ಅಕ್ಷರ *cp, *homedir = ಖಾಲಿ, uidstr[32], buf[4*4096];
	ದೀರ್ಘ ಮುಖವಾಡ;

	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	ಆಗ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'Q':
			ಆದರೆ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಗಾಗಿ (i = 0; handlers[i].handler != ಖಾಲಿ; i++)
				ಬರೆ("%s\n", handlers[i].name);
			ಗಾಗಿ (i = 0; extended_handlers[i].handler != ಖಾಲಿ; i++)
				ಬರೆ("%s\n", extended_handlers[i].name);
			ನಿರ್ಗಮಿಸು(0);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			readonly = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'e':
			log_stderr = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			log_level = log_level_ಸಂಖ್ಯೆ(optarg);
			ಆದರೆ (log_level == SYSLOG_LEVEL_NOT_ಗಣ)
				error("Invalid log level \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			log_facility = log_facility_ಸಂಖ್ಯೆ(optarg);
			ಆದರೆ (log_facility == SYSLOG_FACILITY_NOT_ಗಣ)
				error("Invalid log facility \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (ಅಕ್ಷರ *)ಖಾಲಿ);
			ಬಿಡುಗಡೆ(cp);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			ಆದರೆ (request_allowlist != ಖಾಲಿ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			ಆದರೆ (request_denylist != ಖಾಲಿ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			errno = 0;
			ಮುಖವಾಡ = strtol(optarg, &cp, 8);
			ಆದರೆ (ಮುಖವಾಡ < 0 || ಮುಖವಾಡ > 0777 || *cp != '\0' ||
			    cp == optarg || (ಮುಖವಾಡ == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(ಶೂನ್ಯ)umask((ಬಹುಲಕ_t)ಮುಖವಾಡ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
		ಪೂರ್ವನಿಯೋಜಿತ:
			sftp_server_usage();
		}
	}

	log_init(__progname, log_level, log_facility, log_stderr);

	/*
	 * On platforms where we can, avoid making /proc/self/{mem,maps}
	 * available to the user so that sftp access doesn't automatically
	 * imply arbitrary code execution access that will break
	 * restricted configurations.
	 */
	platform_disable_tracing(1);	/* strict */

	/* Drop any fine-grained privileges we don't need */
	platform_pledge_sftp_server();

	ಆದರೆ ((cp = getenv("SSH_CONNECTION")) != ಖಾಲಿ) {
		client_addr = xstrdup(cp);
		ಆದರೆ ((cp = strchr(client_addr, ' ')) == ಖಾಲಿ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} ಇಲ್ಲದಿದ್ದರೆ
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	ಒಳ = STDIN_FILENO;
	ಹೊರಹೋಗು = STDOUT_FILENO;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	setmode(ಒಳ, O_ದ್ವಿಮಾನ);
	setmode(ಹೊರಹೋಗು, O_ದ್ವಿಮಾನ);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((iqueue = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((oqueue = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆದರೆ (homedir != ಖಾಲಿ) {
		ಆದರೆ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	ಗಾಗಿ (;;) {
		ರಚನೆ pollfd pfd[2];

		memset(pfd, 0, ಗಾತ್ರ pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ಆದರೆ ((r = sshbuf_check_reserve(iqueue, ಗಾತ್ರ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ)) == 0) {
			pfd[0].fd = ಒಳ;
			pfd[0].events = POLLIN;
		}
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_NO_ಬಫರ್_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		ಆದರೆ (olen > 0) {
			pfd[1].fd = ಹೊರಹೋಗು;
			pfd[1].events = POLLOUT;
		}

		ಆದರೆ (poll(pfd, 2, -1) == -1) {
			ಆದರೆ (errno == EINTR)
				ಮುಂದುವರಿ;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		ಆದರೆ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = ಪಠ(ಒಳ, buf, ಗಾತ್ರ buf);
			ಆದರೆ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len == -1) {
				ಆದರೆ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ಆದರೆ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ಲಿಖ(ಹೊರಹೋಗು, sshbuf_ptr(oqueue), olen);
			ಆದರೆ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len == -1) {
				sftp_server_cleanup_exit(1);
				ಆದರೆ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ);
		ಆದರೆ (r == 0)
			process();
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_NO_ಬಫರ್_SPACE)
			fatal_fr(r, "reserve");
	}
}
