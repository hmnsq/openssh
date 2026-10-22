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

ವರ್ಣ *sftp_realpath(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_ಸಂದೇಶ_LENGTH - 1024)

/* Our verbosity */
ಸ್ಥಿರ LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ಸ್ಥಿರ ಸಂರಚನಾ passwd *pw = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *client_addr = ರಿಕ್ತ;

/* input and output queue */
ಸಂರಚನಾ sshbuf *iqueue;
ಸಂರಚನಾ sshbuf *oqueue;

/* Version of client */
ಸ್ಥಿರ u_int version;

/* SSH2_FXP_INIT received */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ init_done;

/* Disable writes */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ readonly;

/* Requests that are allowed/denied */
ಸ್ಥಿರ ವರ್ಣ *request_allowlist, *request_denylist;

/* portable attributes, etc. */
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Stat Stat;

ಸಂರಚನಾ Stat {
	ವರ್ಣ *name;
	ವರ್ಣ *long_name;
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
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_copy_data(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_home_directory(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended_get_users_groups_by_id(uint32_t id);
ಸ್ಥಿರ ಶೂನ್ಯ process_extended(uint32_t id);

ಸಂರಚನಾ sftp_handler {
	ಧ್ರುವ ವರ್ಣ *name;	/* user-visible name for fine-grained perms */
	ಧ್ರುವ ವರ್ಣ *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	ಶೂನ್ಯ (*handler)(uint32_t);
	ಪೂರ್ಣಾಙ್ಕ does_write;		/* if nonzero, banned for readonly mode */
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ರಿಕ್ತ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ರಿಕ್ತ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ರಿಕ್ತ, SSH2_FXP_READ, process_read, 0 },
	{ "write", ರಿಕ್ತ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ರಿಕ್ತ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ರಿಕ್ತ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ರಿಕ್ತ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ರಿಕ್ತ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ರಿಕ್ತ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ರಿಕ್ತ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ರಿಕ್ತ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ರಿಕ್ತ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ರಿಕ್ತ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ರಿಕ್ತ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ರಿಕ್ತ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ರಿಕ್ತ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ರಿಕ್ತ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ರಿಕ್ತ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ರಿಕ್ತ, ರಿಕ್ತ, 0, ರಿಕ್ತ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_data, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ ರಿಕ್ತ, ರಿಕ್ತ, 0, ರಿಕ್ತ, 0 }
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sftp_handler *
extended_handler_byname(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; extended_handlers[i].handler != ರಿಕ್ತ; i++) {
		ಯದಿ (strcmp(name, extended_handlers[i].ext_name) == 0)
			ಪ್ರತ್ಯಾಗಮ &extended_handlers[i];
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
request_permitted(ಧ್ರುವ ಸಂರಚನಾ sftp_handler *h)
{
	ವರ್ಣ *result;

	ಯದಿ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (request_denylist != ರಿಕ್ತ &&
	    ((result = match_list(h->name, request_denylist, ರಿಕ್ತ))) != ರಿಕ್ತ) {
		ಮುಕ್ತ(result);
		verbose("Refusing denylisted %s request", h->name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (request_allowlist != ರಿಕ್ತ &&
	    ((result = match_list(h->name, request_allowlist, ರಿಕ್ತ))) != ರಿಕ್ತ) {
		ಮುಕ್ತ(result);
		debug2("Permitting allowlisted %s request", h->name);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಯದಿ (request_allowlist != ರಿಕ್ತ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
errno_to_portable(ಪೂರ್ಣಾಙ್ಕ unixerrno)
{
	ಪೂರ್ಣಾಙ್ಕ ret = 0;

	ವಿಕಲ್ಪ (unixerrno) {
	ಪಕ್ಷ 0:
		ret = SSH2_FX_OK;
		ಭಙ್ಗ;
	ಪಕ್ಷ ENOENT:
	ಪಕ್ಷ ENOTDIR:
	ಪಕ್ಷ EBADF:
	ಪಕ್ಷ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ಭಙ್ಗ;
	ಪಕ್ಷ EPERM:
	ಪಕ್ಷ EACCES:
	ಪಕ್ಷ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ಭಙ್ಗ;
	ಪಕ್ಷ ENAMETOOLONG:
	ಪಕ್ಷ EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		ಭಙ್ಗ;
	ಪಕ್ಷ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ret = SSH2_FX_FAILURE;
		ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
flags_from_portable(ಪೂರ್ಣಾಙ್ಕ pflags)
{
	ಪೂರ್ಣಾಙ್ಕ flags = 0;

	ಯದಿ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} ಅನ್ಯಥಾ ಯದಿ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} ಅನ್ಯಥಾ ಯದಿ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	ಯದಿ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	ಯದಿ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	ಯದಿ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	ಯದಿ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	ಪ್ರತ್ಯಾಗಮ flags;
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
string_from_portable(ಪೂರ್ಣಾಙ್ಕ pflags)
{
	ಸ್ಥಿರ ವರ್ಣ ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		ಯದಿ (*ret != '\0')			\
			strlcat(ret, ",", ಪರಿಮಾಣ(ret));	\
		strlcat(ret, str, ಪರಿಮಾಣ(ret));		\
	}

	ಯದಿ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	ಯದಿ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	ಯದಿ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	ಯದಿ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	ಯದಿ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	ಯದಿ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	ಪ್ರತ್ಯಾಗಮ ret;
}

/* handle handles */

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ Handle Handle;
ಸಂರಚನಾ Handle {
	ಪೂರ್ಣಾಙ್ಕ use;
	DIR *dirp;
	ಪೂರ್ಣಾಙ್ಕ fd;
	ಪೂರ್ಣಾಙ್ಕ flags;
	ವರ್ಣ *name;
	uint64_t bytes_read, bytes_write;
	ಪೂರ್ಣಾಙ್ಕ next_unused;
};

ಗಣನಾ {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

ಸ್ಥಿರ Handle *handles = ರಿಕ್ತ;
ಸ್ಥಿರ u_int ಅಂಕೆ_handles = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ first_unused_handle = -1;

ಸ್ಥಿರ ಶೂನ್ಯ handle_unused(ಪೂರ್ಣಾಙ್ಕ i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_new(ಪೂರ್ಣಾಙ್ಕ use, ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ flags, DIR *dirp)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (first_unused_handle == -1) {
		ಯದಿ (ಅಂಕೆ_handles + 1 <= ಅಂಕೆ_handles)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಅಂಕೆ_handles++;
		handles = xreallocarray(handles, ಅಂಕೆ_handles, ಪರಿಮಾಣ(Handle));
		handle_unused(ಅಂಕೆ_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	ಪ್ರತ್ಯಾಗಮ i;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_is_ok(ಪೂರ್ಣಾಙ್ಕ i, ಪೂರ್ಣಾಙ್ಕ type)
{
	ಪ್ರತ್ಯಾಗಮ i >= 0 && (u_int)i < ಅಂಕೆ_handles && handles[i].use == type;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_to_string(ಪೂರ್ಣಾಙ್ಕ handle, u_char **stringp, ಪೂರ್ಣಾಙ್ಕ *hlenp)
{
	ಯದಿ (stringp == ರಿಕ್ತ || hlenp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	*stringp = xmalloc(ಪರಿಮಾಣ(int32_t));
	put_u32(*stringp, handle);
	*hlenp = ಪರಿಮಾಣ(int32_t);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_from_string(ಧ್ರುವ u_char *handle, u_int hlen)
{
	ಪೂರ್ಣಾಙ್ಕ val;

	ಯದಿ (hlen != ಪರಿಮಾಣ(int32_t))
		ಪ್ರತ್ಯಾಗಮ -1;
	val = get_u32(handle);
	ಯದಿ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		ಪ್ರತ್ಯಾಗಮ val;
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ವರ್ಣ *
handle_to_name(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		ಪ್ರತ್ಯಾಗಮ handles[handle].name;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ DIR *
handle_to_dir(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_DIR))
		ಪ್ರತ್ಯಾಗಮ handles[handle].dirp;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_to_fd(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE))
		ಪ್ರತ್ಯಾಗಮ handles[handle].fd;
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_to_flags(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE))
		ಪ್ರತ್ಯಾಗಮ handles[handle].flags;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_update_read(ಪೂರ್ಣಾಙ್ಕ handle, ssize_t bytes)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_update_write(ಪೂರ್ಣಾಙ್ಕ handle, ssize_t bytes)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

ಸ್ಥಿರ uint64_t
handle_bytes_read(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE))
		ಪ್ರತ್ಯಾಗಮ (handles[handle].bytes_read);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ uint64_t
handle_bytes_write(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE))
		ಪ್ರತ್ಯಾಗಮ (handles[handle].bytes_write);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_close(ಪೂರ್ಣಾಙ್ಕ handle)
{
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		ಮುಕ್ತ(handles[handle].name);
		handle_unused(handle);
	} ಅನ್ಯಥಾ ಯದಿ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		ಮುಕ್ತ(handles[handle].name);
		handle_unused(handle);
	} ಅನ್ಯಥಾ {
		errno = ENOENT;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_log_close(ಪೂರ್ಣಾಙ್ಕ handle, ವರ್ಣ *emsg)
{
	ಯದಿ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ರಿಕ್ತ ? "" : emsg, emsg == ರಿಕ್ತ ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} ಅನ್ಯಥಾ {
		logit("%s%sclosedir \"%s\"",
		    emsg == ರಿಕ್ತ ? "" : emsg, emsg == ರಿಕ್ತ ? "" : " ",
		    handle_to_name(handle));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_log_exit(ಶೂನ್ಯ)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_handles; i++)
		ಯದಿ (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_handle(ಸಂರಚನಾ sshbuf *queue, ಪೂರ್ಣಾಙ್ಕ *hp)
{
	u_char *handle;
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t hlen;

	*hp = -1;
	ಯದಿ ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	ಮುಕ್ತ(handle);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* send replies */

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
status_to_message(uint32_t status)
{
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ status_messages[] = {
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
	ಪ್ರತ್ಯಾಗಮ (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_status_errmsg(uint32_t id, uint32_t status, ಧ್ರುವ ವರ್ಣ *errmsg)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3("request %u: sent status %u", id, status);
	ಯದಿ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, status)) != 0)
		fatal_fr(r, "compose");
	ಯದಿ (version >= 3) {
		ಯದಿ ((r = sshbuf_put_cstring(ಸಂದೇಶ, errmsg == ರಿಕ್ತ ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_data_or_handle(ವರ್ಣ type, uint32_t id, ಧ್ರುವ u_char *data, ಪೂರ್ಣಾಙ್ಕ dlen)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_data(uint32_t id, ಧ್ರುವ u_char *data, ಪೂರ್ಣಾಙ್ಕ dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_handle(uint32_t id, ಪೂರ್ಣಾಙ್ಕ handle)
{
	u_char *string;
	ಪೂರ್ಣಾಙ್ಕ hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	ಮುಕ್ತ(string);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_names(uint32_t id, ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ, ಧ್ರುವ Stat *stats)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ i, r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, ಎಣಿಕೆ)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, ಎಣಿಕೆ);
	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(ಸಂದೇಶ, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(ಸಂದೇಶ, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_attrib(uint32_t id, ಧ್ರುವ Attrib *a)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_statvfs(uint32_t id, ಸಂರಚನಾ statvfs *st)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	uint64_t flag;
	ಪೂರ್ಣಾಙ್ಕ r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, FSID_TO_ULONG(st->f_fsid))) != 0 ||
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
compose_extension(ಸಂರಚನಾ sshbuf *ಸಂದೇಶ, ಧ್ರುವ ವರ್ಣ *name, ಧ್ರುವ ವರ್ಣ *ver)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ ಸಂರಚನಾ sftp_handler *exthnd;

	ಯದಿ ((exthnd = extended_handler_byname(name)) == ರಿಕ್ತ)
		fatal_f("internal error: no handler for %s", name);
	ಯದಿ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((r = sshbuf_put_cstring(ಸಂದೇಶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* parse incoming */

ಸ್ಥಿರ ಶೂನ್ಯ
process_init(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FILEXFER_VERSION)) != 0)
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
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	ಯದಿ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} ಅನ್ಯಥಾ {
		fd = open(name, flags, mode);
		ಯದಿ (fd == -1) {
			status = errno_to_portable(errno);
		} ಅನ್ಯಥಾ {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ರಿಕ್ತ);
			ಯದಿ (handle < 0) {
				close(fd);
			} ಅನ್ಯಥಾ {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	ಯದಿ (status != SSH2_FX_OK)
		send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_close(uint32_t id)
{
	ಪೂರ್ಣಾಙ್ಕ r, handle, ret, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ರಿಕ್ತ);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_read(uint32_t id)
{
	ಸ್ಥಿರ u_char *buf;
	ಸ್ಥಿರ size_t buflen;
	uint32_t len;
	ಪೂರ್ಣಾಙ್ಕ r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	ಯದಿ ((fd = handle_to_fd(handle)) == -1)
		ಗಚ್ಛ out;
	ಯದಿ (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	ಯದಿ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		ಯದಿ ((buf = realloc(buf, len)) == ರಿಕ್ತ)
			fatal_f("realloc failed");
		buflen = len;
	}
	ಯದಿ (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} ಅನ್ಯಥಾ ಯದಿ ((ret = ಪಠ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (ret == 0) {
		status = SSH2_FX_EOF;
		ಗಚ್ಛ out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	ಯದಿ (status != SSH2_FX_OK)
		send_status(id, status);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r, handle, fd, ret, status;
	u_char *data;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	ಯದಿ (fd < 0)
		status = SSH2_FX_FAILURE;
	ಅನ್ಯಥಾ {
		ಯದಿ (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} ಅನ್ಯಥಾ {
/* XXX ATOMICIO ? */
			ret = ಲಿಖ(fd, data, len);
			ಯದಿ (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} ಅನ್ಯಥಾ ಯದಿ ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} ಅನ್ಯಥಾ {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	ಮುಕ್ತ(data);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_do_stat(uint32_t id, ಪೂರ್ಣಾಙ್ಕ do_lstat)
{
	Attrib a;
	ಸಂರಚನಾ stat st;
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	ಯದಿ (r == -1) {
		status = errno_to_portable(errno);
	} ಅನ್ಯಥಾ {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	ಯದಿ (status != SSH2_FX_OK)
		send_status(id, status);
	ಮುಕ್ತ(name);
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
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ fd, r, handle, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	ಯದಿ (fd >= 0) {
		r = fstat(fd, &st);
		ಯದಿ (r == -1) {
			status = errno_to_portable(errno);
		} ಅನ್ಯಥಾ {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	ಯದಿ (status != SSH2_FX_OK)
		send_status(id, status);
}

ಸ್ಥಿರ ಸಂರಚನಾ timeval *
attrib_to_tv(ಧ್ರುವ Attrib *a)
{
	ಸ್ಥಿರ ಸಂರಚನಾ timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	ಪ್ರತ್ಯಾಗಮ tv;
}

ಸ್ಥಿರ ಸಂರಚನಾ timespec *
attrib_to_ts(ಧ್ರುವ Attrib *a)
{
	ಸ್ಥಿರ ಸಂರಚನಾ timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	ಪ್ರತ್ಯಾಗಮ ts;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_setstat(uint32_t id)
{
	Attrib a;
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, status = SSH2_FX_OK;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ವರ್ಣ buf[64];
		time_t t = a.mtime;

		strftime(buf, ಪರಿಮಾಣ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_fsetstat(uint32_t id)
{
	Attrib a;
	ಪೂರ್ಣಾಙ್ಕ handle, fd, r;
	ಪೂರ್ಣಾಙ್ಕ status = SSH2_FX_OK;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	ಯದಿ (fd < 0)
		status = SSH2_FX_FAILURE;
	ಅನ್ಯಥಾ {
		ವರ್ಣ *name = handle_to_name(handle);

		ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			ಯದಿ (r == -1)
				status = errno_to_portable(errno);
		}
		ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#ಅನ್ಯಥಾ
			r = chmod(name, a.perm & 07777);
#endif
			ಯದಿ (r == -1)
				status = errno_to_portable(errno);
		}
		ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ವರ್ಣ buf[64];
			time_t t = a.mtime;

			strftime(buf, ಪರಿಮಾಣ(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#ಅನ್ಯಥಾ
			r = utimes(name, attrib_to_tv(&a));
#endif
			ಯದಿ (r == -1)
				status = errno_to_portable(errno);
		}
		ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#ಅನ್ಯಥಾ
			r = chown(name, a.uid, a.gid);
#endif
			ಯದಿ (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_opendir(uint32_t id)
{
	DIR *dirp = ರಿಕ್ತ;
	ವರ್ಣ *path;
	ಪೂರ್ಣಾಙ್ಕ r, handle, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &path, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	ಯದಿ (dirp == ರಿಕ್ತ) {
		status = errno_to_portable(errno);
	} ಅನ್ಯಥಾ {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		ಯದಿ (handle < 0) {
			closedir(dirp);
		} ಅನ್ಯಥಾ {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	ಯದಿ (status != SSH2_FX_OK)
		send_status(id, status);
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_readdir(uint32_t id)
{
	DIR *dirp;
	ಸಂರಚನಾ dirent *dp;
	ವರ್ಣ *path;
	ಪೂರ್ಣಾಙ್ಕ r, handle;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	ಯದಿ (dirp == ರಿಕ್ತ || path == ರಿಕ್ತ) {
		send_status(id, SSH2_FX_FAILURE);
	} ಅನ್ಯಥಾ {
		ಸಂರಚನಾ stat st;
		ವರ್ಣ *pathname;
		Stat *stats;
		ಪೂರ್ಣಾಙ್ಕ nstats = 10, ಎಣಿಕೆ = 0, i;

		stats = xcalloc(nstats, ಪರಿಮಾಣ(Stat));
		ಯಾವತ್ ((dp = readdir(dirp)) != ರಿಕ್ತ) {
			ಯದಿ (ಎಣಿಕೆ >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, ಪರಿಮಾಣ(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			ಮುಕ್ತ(pathname);
			ಯದಿ (r == -1)
				ಅನುವರ್ತ;
			stat_to_attrib(&st, &(stats[ಎಣಿಕೆ].attrib));
			stats[ಎಣಿಕೆ].name = xstrdup(dp->d_name);
			stats[ಎಣಿಕೆ].long_name = ls_file(dp->d_name, &st,
			    0, 0, ರಿಕ್ತ, ರಿಕ್ತ);
			ಎಣಿಕೆ++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			ಯದಿ (ಎಣಿಕೆ == 100)
				ಭಙ್ಗ;
		}
		ಯದಿ (ಎಣಿಕೆ > 0) {
			send_names(id, ಎಣಿಕೆ, stats);
			ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
				ಮುಕ್ತ(stats[i].name);
				ಮುಕ್ತ(stats[i].long_name);
			}
		} ಅನ್ಯಥಾ {
			send_status(id, SSH2_FX_EOF);
		}
		ಮುಕ್ತ(stats);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove(uint32_t id)
{
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_mkdir(uint32_t id)
{
	Attrib a;
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, mode, status = SSH2_FX_FAILURE;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_rmdir(uint32_t id)
{
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, status;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_realpath(uint32_t id)
{
	ವರ್ಣ resolvedname[PATH_MAX];
	ವರ್ಣ *path;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &path, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (path[0] == '\0') {
		ಮುಕ್ತ(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	ಯದಿ (sftp_realpath(path, resolvedname) == ರಿಕ್ತ) {
		send_status(id, errno_to_portable(errno));
	} ಅನ್ಯಥಾ {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_rename(uint32_t id)
{
	ವರ್ಣ *oldpath, *newpath;
	ಪೂರ್ಣಾಙ್ಕ r, status;
	ಸಂರಚನಾ stat sb;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &oldpath, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	ಯದಿ (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	ಅನ್ಯಥಾ ಯದಿ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		ಯದಿ (link(oldpath, newpath) == -1) {
			ಯದಿ (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				ಸಂರಚನಾ stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				ಯದಿ (stat(newpath, &st) == -1) {
					ಯದಿ (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					ಅನ್ಯಥಾ
						status = SSH2_FX_OK;
				}
			} ಅನ್ಯಥಾ {
				status = errno_to_portable(errno);
			}
		} ಅನ್ಯಥಾ ಯದಿ (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} ಅನ್ಯಥಾ
			status = SSH2_FX_OK;
	} ಅನ್ಯಥಾ ಯದಿ (stat(newpath, &sb) == -1) {
		ಯದಿ (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		ಅನ್ಯಥಾ
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	ಮುಕ್ತ(oldpath);
	ಮುಕ್ತ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_readlink(uint32_t id)
{
	ಪೂರ್ಣಾಙ್ಕ r, len;
	ವರ್ಣ buf[PATH_MAX];
	ವರ್ಣ *path;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &path, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	ಯದಿ ((len = readlink(path, buf, ಪರಿಮಾಣ(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	ಅನ್ಯಥಾ {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_symlink(uint32_t id)
{
	ವರ್ಣ *oldpath, *newpath;
	ಪೂರ್ಣಾಙ್ಕ r, status;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &oldpath, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(oldpath);
	ಮುಕ್ತ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_posix_rename(uint32_t id)
{
	ವರ್ಣ *oldpath, *newpath;
	ಪೂರ್ಣಾಙ್ಕ r, status;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &oldpath, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(oldpath);
	ಮುಕ್ತ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_statvfs(uint32_t id)
{
	ವರ್ಣ *path;
	ಸಂರಚನಾ statvfs st;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &path, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	ಯದಿ (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	ಅನ್ಯಥಾ
		send_statvfs(id, &st);
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_fstatvfs(uint32_t id)
{
	ಪೂರ್ಣಾಙ್ಕ r, handle, fd;
	ಸಂರಚನಾ statvfs st;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	ಯದಿ ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	ಅನ್ಯಥಾ
		send_statvfs(id, &st);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_hardlink(uint32_t id)
{
	ವರ್ಣ *oldpath, *newpath;
	ಪೂರ್ಣಾಙ್ಕ r, status;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &oldpath, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ಮುಕ್ತ(oldpath);
	ಮುಕ್ತ(newpath);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_fsync(uint32_t id)
{
	ಪೂರ್ಣಾಙ್ಕ handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	ಯದಿ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	ಯದಿ ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	ಅನ್ಯಥಾ ಯದಿ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	ವರ್ಣ *name;
	ಪೂರ್ಣಾಙ್ಕ r, status = SSH2_FX_OK;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &name, ರಿಕ್ತ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		ಗಚ್ಛ out;
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ವರ್ಣ buf[64];
		time_t t = a.mtime;

		strftime(buf, ಪರಿಮಾಣ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
	ಯದಿ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		ಯದಿ (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	ಮುಕ್ತ(name);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_limits(uint32_t id)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;
	uint64_t nfiles = 0;
#ಯದಿ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ಸಂರಚನಾ rlimit rlim;
#endif

	debug("request %u: limits", id);

#ಯದಿ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ಯದಿ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_ಸಂದೇಶ_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, SFTP_MAX_ಸಂದೇಶ_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(ಸಂದೇಶ, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_expand(uint32_t id)
{
	ವರ್ಣ cwd[PATH_MAX], resolvedname[PATH_MAX];
	ವರ್ಣ *path, *npath;
	ಪೂರ್ಣಾಙ್ಕ r;
	Stat s;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &path, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (getcwd(cwd, ಪರಿಮಾಣ(cwd)) == ರಿಕ್ತ) {
		send_status(id, errno_to_portable(errno));
		ಗಚ್ಛ out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	ಯದಿ (path[0] == '\0') {
		/* empty path */
		ಮುಕ್ತ(path);
		path = xstrdup(".");
	} ಅನ್ಯಥಾ ಯದಿ (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		ಯದಿ (strcmp(path, "~") == 0) {
			ಮುಕ್ತ(path);
			path = xstrdup(cwd);
		} ಅನ್ಯಥಾ ಯದಿ (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			ಮುಕ್ತ(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			ಮುಕ್ತ(npath);
		} ಅನ್ಯಥಾ {
			/* ~user expansions */
			ಯದಿ (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				ಗಚ್ಛ out;
			}
			ಮುಕ್ತ(path);
			path = npath;
		}
	} ಅನ್ಯಥಾ ಯದಿ (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		ಮುಕ್ತ(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	ಯದಿ (sftp_realpath(path, resolvedname) == ರಿಕ್ತ) {
		send_status(id, errno_to_portable(errno));
		ಗಚ್ಛ out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	ಪೂರ್ಣಾಙ್ಕ read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	ಪೂರ್ಣಾಙ್ಕ r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	ಸಂರಚನಾ stat st_read, st_write;

	ಯದಿ ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_to_name(read_handle), read_handle,
	    (unsigned long long)read_off, (unsigned long long)read_len,
	    handle_to_name(write_handle), write_handle,
	    (unsigned long long)write_off);

	/* For read length of 0, we read until EOF. */
	ಯದಿ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} ಅನ್ಯಥಾ
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	ಯದಿ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		ಗಚ್ಛ out;
	}
	ಯದಿ (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ (read_handle == write_handle ||
	    !strcmp(handle_to_name(read_handle), handle_to_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_to_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_to_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		status = SSH2_FX_FAILURE;
		ಗಚ್ಛ out;
	}

	ಯದಿ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		ಗಚ್ಛ out;
	}

	/* Process the request in chunks. */
	ಯಾವತ್ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(ಪರಿಮಾಣ(buf), read_len);
		read_len -= len;

		ret = atomicio(ಪಠ, read_fd, buf, len);
		ಯದಿ (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ ಯದಿ (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ಭಙ್ಗ;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		ಯದಿ (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			ಭಙ್ಗ;
		}
		handle_update_write(write_handle, len);
	}

	ಯದಿ (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_home_directory(uint32_t id)
{
	ವರ್ಣ *username;
	ಸಂರಚನಾ passwd *user_pw;
	ಪೂರ್ಣಾಙ್ಕ r;
	Stat s;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &username, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	ಯದಿ (username[0] == '\0') {
		user_pw = pw;
	} ಅನ್ಯಥಾ ಯದಿ ((user_pw = getpwnam(username)) == ರಿಕ್ತ) {
		send_status(id, SSH2_FX_FAILURE);
		ಗಚ್ಛ out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	ಮುಕ್ತ(username);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extended_get_users_groups_by_id(uint32_t id)
{
	ಸಂರಚನಾ passwd *user_pw;
	ಸಂರಚನಾ group *gr;
	ಸಂರಚನಾ sshbuf *uids, *gids, *usernames, *groupnames, *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int n, nusers = 0, ngroups = 0;
	ಧ್ರುವ ವರ್ಣ *name;

	ಯದಿ ((usernames = sshbuf_new()) == ರಿಕ್ತ ||
	    (groupnames = sshbuf_new()) == ರಿಕ್ತ ||
	    (ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	ಯಾವತ್ (sshbuf_len(uids) != 0) {
		ಯದಿ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ರಿಕ್ತ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		ಯದಿ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	ಯಾವತ್ (sshbuf_len(gids) != 0) {
		ಯದಿ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ರಿಕ್ತ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		ಯದಿ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
	ವರ್ಣ *request;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ ಸಂರಚನಾ sftp_handler *exthand;

	ಯದಿ ((r = sshbuf_get_cstring(iqueue, &request, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ ((exthand = extended_handler_byname(request)) == ರಿಕ್ತ) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} ಅನ್ಯಥಾ {
		ಯದಿ (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		ಅನ್ಯಥಾ
			exthand->handler(id);
	}
	ಮುಕ್ತ(request);
}

/* stolen from ssh-agent */

ಸ್ಥಿರ ಶೂನ್ಯ
process(ಶೂನ್ಯ)
{
	u_int ಸಂದೇಶ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ಧ್ರುವ u_char *cp;
	ಪೂರ್ಣಾಙ್ಕ i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	ಯದಿ (buf_len < 5)
		ಪ್ರತ್ಯಾಗಮ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ಸಂದೇಶ_len = get_u32(cp);
	ಯದಿ (ಸಂದೇಶ_len > SFTP_MAX_ಸಂದೇಶ_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	ಯದಿ (buf_len < ಸಂದೇಶ_len + 4)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	ಯದಿ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_FXP_EXTENDED:
		ಯದಿ (!init_done)
			fatal("Received extended request before init");
		ಯದಿ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಯದಿ (!init_done)
			fatal("Received %u request before init", type);
		ಯದಿ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		ಪ್ರತಿ (i = 0; handlers[i].handler != ರಿಕ್ತ; i++) {
			ಯದಿ (type == handlers[i].type) {
				ಯದಿ (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} ಅನ್ಯಥಾ {
					handlers[i].handler(id);
				}
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (handlers[i].handler == ರಿಕ್ತ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	ಯದಿ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ಯದಿ (ಸಂದೇಶ_len < consumed) {
		error("msg_len %u < consumed %u", ಸಂದೇಶ_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	ಯದಿ (ಸಂದೇಶ_len > consumed &&
	    (r = sshbuf_consume(iqueue, ಸಂದೇಶ_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
ಶೂನ್ಯ
sftp_server_cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	ಯದಿ (pw != ರಿಕ್ತ && client_addr != ರಿಕ್ತ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sftp_server_usage(ಶೂನ್ಯ)
{
	ಬಾಹ್ಯ ವರ್ಣ *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_server_main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ಸಂರಚನಾ passwd *user_pw)
{
	ಪೂರ್ಣಾಙ್ಕ i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	ವರ್ಣ *cp, *homedir = ರಿಕ್ತ, uidstr[32], buf[4*4096];
	long mask;

	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ವರ್ಣ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	ಯಾವತ್ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'Q':
			ಯದಿ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			ಪ್ರತಿ (i = 0; handlers[i].handler != ರಿಕ್ತ; i++)
				printf("%s\n", handlers[i].name);
			ಪ್ರತಿ (i = 0; extended_handlers[i].handler != ರಿಕ್ತ; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			readonly = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'e':
			log_stderr = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			log_level = log_level_ಸಂಖ್ಯೆ(optarg);
			ಯದಿ (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			log_facility = log_facility_ಸಂಖ್ಯೆ(optarg);
			ಯದಿ (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (ವರ್ಣ *)ರಿಕ್ತ);
			ಮುಕ್ತ(cp);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			ಯದಿ (request_allowlist != ರಿಕ್ತ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			ಯದಿ (request_denylist != ರಿಕ್ತ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			ಯದಿ (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(ಶೂನ್ಯ)umask((mode_t)mask);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
		ಸ್ವಭಾವ:
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

	ಯದಿ ((cp = getenv("SSH_CONNECTION")) != ರಿಕ್ತ) {
		client_addr = xstrdup(cp);
		ಯದಿ ((cp = strchr(client_addr, ' ')) == ರಿಕ್ತ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} ಅನ್ಯಥಾ
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_ದ್ವಿಮಾನ);
	setmode(out, O_ದ್ವಿಮಾನ);
#endif

	ಯದಿ ((iqueue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((oqueue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯದಿ (homedir != ರಿಕ್ತ) {
		ಯದಿ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	ಪ್ರತಿ (;;) {
		ಸಂರಚನಾ pollfd pfd[2];

		memset(pfd, 0, ಪರಿಮಾಣ pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ಯದಿ ((r = sshbuf_check_reserve(iqueue, ಪರಿಮಾಣ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_ಸಂದೇಶ_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		ಯದಿ (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		ಯದಿ (poll(pfd, 2, -1) == -1) {
			ಯದಿ (errno == EINTR)
				ಅನುವರ್ತ;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		ಯದಿ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = ಪಠ(in, buf, ಪರಿಮಾಣ buf);
			ಯದಿ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} ಅನ್ಯಥಾ ಯದಿ (len == -1) {
				ಯದಿ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ಯದಿ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ಲಿಖ(out, sshbuf_ptr(oqueue), olen);
			ಯದಿ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} ಅನ್ಯಥಾ ಯದಿ (len == -1) {
				sftp_server_cleanup_exit(1);
				ಯದಿ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_ಸಂದೇಶ_LENGTH);
		ಯದಿ (r == 0)
			process();
		ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
