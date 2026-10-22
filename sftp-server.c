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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/statvfs.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"

ਅੱਖਰ *sftp_realpath(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_MAX_READ_ਲੰਮਾਈ (SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ - 1024)

/* Our verbosity */
ਸਥਿਰ LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ਸਥਿਰ ਬਣਤਰ passwd *pw = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *client_addr = ਨਿਰਾ;

/* input and output queue */
ਬਣਤਰ sshbuf *iqueue;
ਬਣਤਰ sshbuf *oqueue;

/* Version of client */
ਸਥਿਰ u_int ਸੰਸਕਰਣ;

/* SSH2_FXP_INIT received */
ਸਥਿਰ ਪੂਰਨ init_ਪੂਰਾ;

/* Disable writes */
ਸਥਿਰ ਪੂਰਨ readonly;

/* Requests that are allowed/denied */
ਸਥਿਰ ਅੱਖਰ *request_allowlist, *request_denylist;

/* portable attributes, etc. */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Stat Stat;

ਬਣਤਰ Stat {
	ਅੱਖਰ *name;
	ਅੱਖਰ *long_name;
	Attrib attrib;
};

/* Packet handlers */
ਸਥਿਰ ਖਾਲੀ process_open(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_close(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_read(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_write(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_stat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_lstat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_fstat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_setstat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_fsetstat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_opendir(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_readdir(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_remove(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_mkdir(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_rmdir(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_realpath(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_rename(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_readlink(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_symlink(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_posix_rename(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_statvfs(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_fstatvfs(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_hardlink(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_fsync(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_lsetstat(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_limits(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_expand(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_copy_ਅੰਕੜੇ(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_home_directory(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended_get_users_groups_by_id(uint32_t id);
ਸਥਿਰ ਖਾਲੀ process_extended(uint32_t id);

ਬਣਤਰ sftp_handler {
	ਅਚਲ ਅੱਖਰ *name;	/* user-visible name for fine-grained perms */
	ਅਚਲ ਅੱਖਰ *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	ਖਾਲੀ (*handler)(uint32_t);
	ਪੂਰਨ does_write;		/* if nonzero, banned for readonly mode */
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ਨਿਰਾ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ਨਿਰਾ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ਨਿਰਾ, SSH2_FXP_READ, process_read, 0 },
	{ "write", ਨਿਰਾ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ਨਿਰਾ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ਨਿਰਾ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ਨਿਰਾ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ਨਿਰਾ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ਨਿਰਾ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ਨਿਰਾ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ਨਿਰਾ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ਨਿਰਾ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ਨਿਰਾ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ਨਿਰਾ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ਨਿਰਾ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ਨਿਰਾ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ਨਿਰਾ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ਨਿਰਾ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ਨਿਰਾ, ਨਿਰਾ, 0, ਨਿਰਾ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ਸਥਿਰ ਅਚਲ ਬਣਤਰ sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_ਅੰਕੜੇ, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ ਨਿਰਾ, ਨਿਰਾ, 0, ਨਿਰਾ, 0 }
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sftp_handler *
extended_handler_byname(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; extended_handlers[i].handler != ਨਿਰਾ; i++) {
		ਜੇ (strcmp(name, extended_handlers[i].ext_name) == 0)
			ਵਾਪਸ &extended_handlers[i];
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
request_permitted(ਅਚਲ ਬਣਤਰ sftp_handler *h)
{
	ਅੱਖਰ *ਨਤੀਜਾ;

	ਜੇ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		ਵਾਪਸ 0;
	}
	ਜੇ (request_denylist != ਨਿਰਾ &&
	    ((ਨਤੀਜਾ = ਮੇਲ_list(h->name, request_denylist, ਨਿਰਾ))) != ਨਿਰਾ) {
		ਮੁਕਤ(ਨਤੀਜਾ);
		verbose("Refusing denylisted %s request", h->name);
		ਵਾਪਸ 0;
	}
	ਜੇ (request_allowlist != ਨਿਰਾ &&
	    ((ਨਤੀਜਾ = ਮੇਲ_list(h->name, request_allowlist, ਨਿਰਾ))) != ਨਿਰਾ) {
		ਮੁਕਤ(ਨਤੀਜਾ);
		debug2("Permitting allowlisted %s request", h->name);
		ਵਾਪਸ 1;
	}
	ਜੇ (request_allowlist != ਨਿਰਾ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
errno_ਮੰਜ਼ਿਲ_portable(ਪੂਰਨ unixerrno)
{
	ਪੂਰਨ ret = 0;

	ਚੋਣ (unixerrno) {
	ਹਾਲਤ 0:
		ret = SSH2_FX_OK;
		ਰੋਕੋ;
	ਹਾਲਤ ENOENT:
	ਹਾਲਤ ENOTDIR:
	ਹਾਲਤ EBADF:
	ਹਾਲਤ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ਰੋਕੋ;
	ਹਾਲਤ EPERM:
	ਹਾਲਤ EACCES:
	ਹਾਲਤ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ਰੋਕੋ;
	ਹਾਲਤ ENAMETOOLONG:
	ਹਾਲਤ EINVAL:
		ret = SSH2_FX_BAD_ਸੁਨੇਹਾ;
		ਰੋਕੋ;
	ਹਾਲਤ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ਰੋਕੋ;
	ਮੂਲ:
		ret = SSH2_FX_FAILURE;
		ਰੋਕੋ;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
flags_from_portable(ਪੂਰਨ pflags)
{
	ਪੂਰਨ flags = 0;

	ਜੇ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} ਨਹੀਂਤਾਂ ਜੇ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} ਨਹੀਂਤਾਂ ਜੇ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	ਜੇ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	ਜੇ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	ਜੇ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	ਜੇ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	ਵਾਪਸ flags;
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
string_from_portable(ਪੂਰਨ pflags)
{
	ਸਥਿਰ ਅੱਖਰ ret[128];

	*ret = '\0';

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PAPPEND(str)	{				\
		ਜੇ (*ret != '\0')			\
			strlcat(ret, ",", ਆਕਾਰ(ret));	\
		strlcat(ret, str, ਆਕਾਰ(ret));		\
	}

	ਜੇ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	ਜੇ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	ਜੇ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	ਜੇ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	ਜੇ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	ਜੇ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	ਵਾਪਸ ret;
}

/* handle handles */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ Handle Handle;
ਬਣਤਰ Handle {
	ਪੂਰਨ use;
	DIR *dirp;
	ਪੂਰਨ fd;
	ਪੂਰਨ flags;
	ਅੱਖਰ *name;
	uint64_t ਬਾਈਟਾਂ_read, ਬਾਈਟਾਂ_write;
	ਪੂਰਨ ਅਗਲਾ_ਅਣਵਰਤਿਆ;
};

ਗਿਣਤੀ {
	HANDLE_ਅਣਵਰਤਿਆ,
	HANDLE_DIR,
	HANDLE_FILE
};

ਸਥਿਰ Handle *handles = ਨਿਰਾ;
ਸਥਿਰ u_int ਅੰਕ_handles = 0;
ਸਥਿਰ ਪੂਰਨ ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle = -1;

ਸਥਿਰ ਖਾਲੀ handle_ਅਣਵਰਤਿਆ(ਪੂਰਨ i)
{
	handles[i].use = HANDLE_ਅਣਵਰਤਿਆ;
	handles[i].ਅਗਲਾ_ਅਣਵਰਤਿਆ = ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle;
	ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle = i;
}

ਸਥਿਰ ਪੂਰਨ
handle_new(ਪੂਰਨ use, ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ fd, ਪੂਰਨ flags, DIR *dirp)
{
	ਪੂਰਨ i;

	ਜੇ (ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle == -1) {
		ਜੇ (ਅੰਕ_handles + 1 <= ਅੰਕ_handles)
			ਵਾਪਸ -1;
		ਅੰਕ_handles++;
		handles = xreallocarray(handles, ਅੰਕ_handles, ਆਕਾਰ(Handle));
		handle_ਅਣਵਰਤਿਆ(ਅੰਕ_handles - 1);
	}

	i = ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle;
	ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle = handles[i].ਅਗਲਾ_ਅਣਵਰਤਿਆ;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].ਬਾਈਟਾਂ_read = handles[i].ਬਾਈਟਾਂ_write = 0;

	ਵਾਪਸ i;
}

ਸਥਿਰ ਪੂਰਨ
handle_is_ok(ਪੂਰਨ i, ਪੂਰਨ type)
{
	ਵਾਪਸ i >= 0 && (u_int)i < ਅੰਕ_handles && handles[i].use == type;
}

ਸਥਿਰ ਪੂਰਨ
handle_ਮੰਜ਼ਿਲ_string(ਪੂਰਨ handle, u_char **stringp, ਪੂਰਨ *hlenp)
{
	ਜੇ (stringp == ਨਿਰਾ || hlenp == ਨਿਰਾ)
		ਵਾਪਸ -1;
	*stringp = xmalloc(ਆਕਾਰ(int32_t));
	put_u32(*stringp, handle);
	*hlenp = ਆਕਾਰ(int32_t);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
handle_from_string(ਅਚਲ u_char *handle, u_int hlen)
{
	ਪੂਰਨ val;

	ਜੇ (hlen != ਆਕਾਰ(int32_t))
		ਵਾਪਸ -1;
	val = get_u32(handle);
	ਜੇ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		ਵਾਪਸ val;
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਅੱਖਰ *
handle_ਮੰਜ਼ਿਲ_name(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		ਵਾਪਸ handles[handle].name;
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ DIR *
handle_ਮੰਜ਼ਿਲ_dir(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_DIR))
		ਵਾਪਸ handles[handle].dirp;
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
handle_ਮੰਜ਼ਿਲ_fd(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE))
		ਵਾਪਸ handles[handle].fd;
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
handle_ਮੰਜ਼ਿਲ_flags(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE))
		ਵਾਪਸ handles[handle].flags;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
handle_update_read(ਪੂਰਨ handle, ssize_t ਬਾਈਟਾਂ)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE) && ਬਾਈਟਾਂ > 0)
		handles[handle].ਬਾਈਟਾਂ_read += ਬਾਈਟਾਂ;
}

ਸਥਿਰ ਖਾਲੀ
handle_update_write(ਪੂਰਨ handle, ssize_t ਬਾਈਟਾਂ)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE) && ਬਾਈਟਾਂ > 0)
		handles[handle].ਬਾਈਟਾਂ_write += ਬਾਈਟਾਂ;
}

ਸਥਿਰ uint64_t
handle_ਬਾਈਟਾਂ_read(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE))
		ਵਾਪਸ (handles[handle].ਬਾਈਟਾਂ_read);
	ਵਾਪਸ 0;
}

ਸਥਿਰ uint64_t
handle_ਬਾਈਟਾਂ_write(ਪੂਰਨ handle)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE))
		ਵਾਪਸ (handles[handle].ਬਾਈਟਾਂ_write);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
handle_close(ਪੂਰਨ handle)
{
	ਪੂਰਨ ret = -1;

	ਜੇ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		ਮੁਕਤ(handles[handle].name);
		handle_ਅਣਵਰਤਿਆ(handle);
	} ਨਹੀਂਤਾਂ ਜੇ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		ਮੁਕਤ(handles[handle].name);
		handle_ਅਣਵਰਤਿਆ(handle);
	} ਨਹੀਂਤਾਂ {
		errno = ENOENT;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
handle_log_close(ਪੂਰਨ handle, ਅੱਖਰ *emsg)
{
	ਜੇ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ਨਿਰਾ ? "" : emsg, emsg == ਨਿਰਾ ? "" : " ",
		    handle_ਮੰਜ਼ਿਲ_name(handle),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)handle_ਬਾਈਟਾਂ_read(handle),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)handle_ਬਾਈਟਾਂ_write(handle));
	} ਨਹੀਂਤਾਂ {
		logit("%s%sclosedir \"%s\"",
		    emsg == ਨਿਰਾ ? "" : emsg, emsg == ਨਿਰਾ ? "" : " ",
		    handle_ਮੰਜ਼ਿਲ_name(handle));
	}
}

ਸਥਿਰ ਖਾਲੀ
handle_log_exit(ਖਾਲੀ)
{
	u_int i;

	ਲਈ (i = 0; i < ਅੰਕ_handles; i++)
		ਜੇ (handles[i].use != HANDLE_ਅਣਵਰਤਿਆ)
			handle_log_close(i, "forced");
}

ਸਥਿਰ ਪੂਰਨ
get_handle(ਬਣਤਰ sshbuf *ਕਤਾਰ, ਪੂਰਨ *hp)
{
	u_char *handle;
	ਪੂਰਨ r;
	ਮਾਪ_t hlen;

	*hp = -1;
	ਜੇ ((r = sshbuf_get_string(ਕਤਾਰ, &handle, &hlen)) != 0)
		ਵਾਪਸ r;
	ਜੇ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	ਮੁਕਤ(handle);
	ਵਾਪਸ 0;
}

/* send replies */

ਸਥਿਰ ਖਾਲੀ
send_ਸੁਨੇਹਾ(ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
ਸਥਿਤੀ_ਮੰਜ਼ਿਲ_ਸੁਨੇਹਾ(uint32_t ਸਥਿਤੀ)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ ਸਥਿਤੀ_messages[] = {
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
	ਵਾਪਸ (ਸਥਿਤੀ_messages[MINIMUM(ਸਥਿਤੀ,SSH2_FX_MAX)]);
}

ਸਥਿਰ ਖਾਲੀ
send_ਸਥਿਤੀ_errmsg(uint32_t id, uint32_t ਸਥਿਤੀ, ਅਚਲ ਅੱਖਰ *errmsg)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	debug3("request %u: sent status %u", id, ਸਥਿਤੀ);
	ਜੇ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (ਸਥਿਤੀ != SSH2_FX_OK && ਸਥਿਤੀ != SSH2_FX_EOF))
		logit("sent status %s", ਸਥਿਤੀ_ਮੰਜ਼ਿਲ_ਸੁਨੇਹਾ(ਸਥਿਤੀ));
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_ਸਥਿਤੀ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, ਸਥਿਤੀ)) != 0)
		fatal_fr(r, "compose");
	ਜੇ (ਸੰਸਕਰਣ >= 3) {
		ਜੇ ((r = sshbuf_put_cstring(ਸੁਨੇਹਾ, errmsg == ਨਿਰਾ ?
		    ਸਥਿਤੀ_ਮੰਜ਼ਿਲ_ਸੁਨੇਹਾ(ਸਥਿਤੀ) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_ਸਥਿਤੀ(uint32_t id, uint32_t ਸਥਿਤੀ)
{
	send_ਸਥਿਤੀ_errmsg(id, ਸਥਿਤੀ, ਨਿਰਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_ਅੰਕੜੇ_or_handle(ਅੱਖਰ type, uint32_t id, ਅਚਲ u_char *ਅੰਕੜੇ, ਪੂਰਨ dlen)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, type)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਅੰਕੜੇ, dlen)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_ਅੰਕੜੇ(uint32_t id, ਅਚਲ u_char *ਅੰਕੜੇ, ਪੂਰਨ dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_ਅੰਕੜੇ_or_handle(SSH2_FXP_ਅੰਕੜੇ, id, ਅੰਕੜੇ, dlen);
}

ਸਥਿਰ ਖਾਲੀ
send_handle(uint32_t id, ਪੂਰਨ handle)
{
	u_char *string;
	ਪੂਰਨ hlen;

	handle_ਮੰਜ਼ਿਲ_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_ਅੰਕੜੇ_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	ਮੁਕਤ(string);
}

ਸਥਿਰ ਖਾਲੀ
send_ਨਾਂ(uint32_t id, ਪੂਰਨ ਗਿਣਤੀ_2, ਅਚਲ Stat *stats)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ i, r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, ਗਿਣਤੀ_2)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, ਗਿਣਤੀ_2);
	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
		ਜੇ ((r = sshbuf_put_cstring(ਸੁਨੇਹਾ, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(ਸੁਨੇਹਾ, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_attrib(uint32_t id, ਅਚਲ Attrib *a)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, a)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_statvfs(uint32_t id, ਬਣਤਰ statvfs *st)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	uint64_t flag;
	ਪੂਰਨ r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED_ਜਵਾਬ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, FSID_ਮੰਜ਼ਿਲ_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, flag)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ਸਥਿਰ ਪੂਰਨ
compose_extension(ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ, ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ *ver)
{
	ਪੂਰਨ r;
	ਅਚਲ ਬਣਤਰ sftp_handler *exthnd;

	ਜੇ ((exthnd = extended_handler_byname(name)) == ਨਿਰਾ)
		fatal_f("internal error: no handler for %s", name);
	ਜੇ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		ਵਾਪਸ 0;
	}
	ਜੇ ((r = sshbuf_put_cstring(ਸੁਨੇਹਾ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	ਵਾਪਸ 0;
}

/* parse incoming */

ਸਥਿਰ ਖਾਲੀ
process_init(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_u32(iqueue, &ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", ਸੰਸਕਰਣ);
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, SSH2_FILEXFER_ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(ਸੁਨੇਹਾ, "posix-rename@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "statvfs@openssh.com", "2");
	compose_extension(ਸੁਨੇਹਾ, "fstatvfs@openssh.com", "2");
	compose_extension(ਸੁਨੇਹਾ, "hardlink@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "fsync@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "lsetstat@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "limits@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "expand-path@openssh.com", "1");
	compose_extension(ਸੁਨੇਹਾ, "copy-data", "1");
	compose_extension(ਸੁਨੇਹਾ, "home-directory", "1");
	compose_extension(ਸੁਨੇਹਾ, "users-groups-by-id@openssh.com", "1");

	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	ਅੱਖਰ *name;
	ਪੂਰਨ r, handle, fd, flags, ਬਹੁਲਕ, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	ਬਹੁਲਕ = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), ਬਹੁਲਕ);
	ਜੇ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		ਸਥਿਤੀ = SSH2_FX_PERMISSION_DENIED;
	} ਨਹੀਂਤਾਂ {
		fd = open(name, flags, ਬਹੁਲਕ);
		ਜੇ (fd == -1) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		} ਨਹੀਂਤਾਂ {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ਨਿਰਾ);
			ਜੇ (handle < 0) {
				close(fd);
			} ਨਹੀਂਤਾਂ {
				send_handle(id, handle);
				ਸਥਿਤੀ = SSH2_FX_OK;
			}
		}
	}
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_close(uint32_t id)
{
	ਪੂਰਨ r, handle, ret, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ਨਿਰਾ);
	ret = handle_close(handle);
	ਸਥਿਤੀ = (ret == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਖਾਲੀ
process_read(uint32_t id)
{
	ਸਥਿਰ u_char *buf;
	ਸਥਿਰ ਮਾਪ_t buflen;
	uint32_t len;
	ਪੂਰਨ r, handle, fd, ret, ਸਥਿਤੀ = SSH2_FX_FAILURE;
	uint64_t off;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_ਮੰਜ਼ਿਲ_name(handle), handle, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)off, len);
	ਜੇ ((fd = handle_ਮੰਜ਼ਿਲ_fd(handle)) == -1)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (len > SFTP_MAX_READ_ਲੰਮਾਈ) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_ਲੰਮਾਈ);
		len = SFTP_MAX_READ_ਲੰਮਾਈ;
	}
	ਜੇ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		ਜੇ ((buf = realloc(buf, len)) == ਨਿਰਾ)
			fatal_f("realloc failed");
		buflen = len;
	}
	ਜੇ (lseek(fd, off, SEEK_SET) == -1) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("seek \"%.100s\": %s", handle_ਮੰਜ਼ਿਲ_name(handle),
		    strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} ਨਹੀਂਤਾਂ ਜੇ ((ret = ਪਠ(fd, buf, len)) == -1) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("read \"%.100s\": %s", handle_ਮੰਜ਼ਿਲ_name(handle),
		    strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (ret == 0) {
		ਸਥਿਤੀ = SSH2_FX_EOF;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	send_ਅੰਕੜੇ(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	ਸਥਿਤੀ = SSH2_FX_OK;
 ਬਾਹਰਲਾ:
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਖਾਲੀ
process_write(uint32_t id)
{
	uint64_t off;
	ਮਾਪ_t len;
	ਪੂਰਨ r, handle, fd, ret, ਸਥਿਤੀ;
	u_char *ਅੰਕੜੇ;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &ਅੰਕੜੇ, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_ਮੰਜ਼ਿਲ_name(handle), handle, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)off, len);
	fd = handle_ਮੰਜ਼ਿਲ_fd(handle);

	ਜੇ (fd < 0)
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
	ਨਹੀਂਤਾਂ {
		ਜੇ (!(handle_ਮੰਜ਼ਿਲ_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
			error_f("seek \"%.100s\": %s", handle_ਮੰਜ਼ਿਲ_name(handle),
			    strerror(errno));
		} ਨਹੀਂਤਾਂ {
/* XXX ATOMICIO ? */
			ret = ਲਿਖ(fd, ਅੰਕੜੇ, len);
			ਜੇ (ret == -1) {
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_ਮੰਜ਼ਿਲ_name(handle), strerror(errno));
			} ਨਹੀਂਤਾਂ ਜੇ ((ਮਾਪ_t)ret == len) {
				ਸਥਿਤੀ = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} ਨਹੀਂਤਾਂ {
				debug2_f("nothing at all written");
				ਸਥਿਤੀ = SSH2_FX_FAILURE;
			}
		}
	}
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(ਅੰਕੜੇ);
}

ਸਥਿਰ ਖਾਲੀ
process_do_stat(uint32_t id, ਪੂਰਨ do_lstat)
{
	Attrib a;
	ਬਣਤਰ stat st;
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	ਜੇ (r == -1) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	} ਨਹੀਂਤਾਂ {
		stat_ਮੰਜ਼ਿਲ_attrib(&st, &a);
		send_attrib(id, &a);
		ਸਥਿਤੀ = SSH2_FX_OK;
	}
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ਸਥਿਰ ਖਾਲੀ
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ਸਥਿਰ ਖਾਲੀ
process_fstat(uint32_t id)
{
	Attrib a;
	ਬਣਤਰ stat st;
	ਪੂਰਨ fd, r, handle, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_ਮੰਜ਼ਿਲ_name(handle), handle);
	fd = handle_ਮੰਜ਼ਿਲ_fd(handle);
	ਜੇ (fd >= 0) {
		r = fstat(fd, &st);
		ਜੇ (r == -1) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		} ਨਹੀਂਤਾਂ {
			stat_ਮੰਜ਼ਿਲ_attrib(&st, &a);
			send_attrib(id, &a);
			ਸਥਿਤੀ = SSH2_FX_OK;
		}
	}
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਬਣਤਰ timeval *
attrib_ਮੰਜ਼ਿਲ_tv(ਅਚਲ Attrib *a)
{
	ਸਥਿਰ ਬਣਤਰ timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	ਵਾਪਸ tv;
}

ਸਥਿਰ ਬਣਤਰ timespec *
attrib_ਮੰਜ਼ਿਲ_ts(ਅਚਲ Attrib *a)
{
	ਸਥਿਰ ਬਣਤਰ timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	ਵਾਪਸ ts;
}

ਸਥਿਰ ਖਾਲੀ
process_setstat(uint32_t id)
{
	Attrib a;
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਸਥਿਤੀ = SSH2_FX_OK;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ਮਾਪ) {
		logit("set \"%s\" size %llu",
		    name, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)a.ਮਾਪ);
		r = truncate(name, a.ਮਾਪ);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ਅੱਖਰ buf[64];
		time_t t = a.mtime;

		strftime(buf, ਆਕਾਰ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_ਮੰਜ਼ਿਲ_tv(&a));
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_fsetstat(uint32_t id)
{
	Attrib a;
	ਪੂਰਨ handle, fd, r;
	ਪੂਰਨ ਸਥਿਤੀ = SSH2_FX_OK;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_ਮੰਜ਼ਿਲ_fd(handle);
	ਜੇ (fd < 0)
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
	ਨਹੀਂਤਾਂ {
		ਅੱਖਰ *name = handle_ਮੰਜ਼ਿਲ_name(handle);

		ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ਮਾਪ) {
			logit("set \"%s\" size %llu",
			    name, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)a.ਮਾਪ);
			r = ftruncate(fd, a.ਮਾਪ);
			ਜੇ (r == -1)
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		}
		ਜੇ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#ਨਹੀਂਤਾਂ
			r = chmod(name, a.perm & 07777);
#ਜੇ_ਅੰਤ
			ਜੇ (r == -1)
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		}
		ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ਅੱਖਰ buf[64];
			time_t t = a.mtime;

			strftime(buf, ਆਕਾਰ(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FUTIMES
			r = futimes(fd, attrib_ਮੰਜ਼ਿਲ_tv(&a));
#ਨਹੀਂਤਾਂ
			r = utimes(name, attrib_ਮੰਜ਼ਿਲ_tv(&a));
#ਜੇ_ਅੰਤ
			ਜੇ (r == -1)
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		}
		ਜੇ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#ਨਹੀਂਤਾਂ
			r = chown(name, a.uid, a.gid);
#ਜੇ_ਅੰਤ
			ਜੇ (r == -1)
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		}
	}
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਖਾਲੀ
process_opendir(uint32_t id)
{
	DIR *dirp = ਨਿਰਾ;
	ਅੱਖਰ *ਰਸਤਾ;
	ਪੂਰਨ r, handle, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &ਰਸਤਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", ਰਸਤਾ);
	dirp = opendir(ਰਸਤਾ);
	ਜੇ (dirp == ਨਿਰਾ) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	} ਨਹੀਂਤਾਂ {
		handle = handle_new(HANDLE_DIR, ਰਸਤਾ, 0, 0, dirp);
		ਜੇ (handle < 0) {
			closedir(dirp);
		} ਨਹੀਂਤਾਂ {
			send_handle(id, handle);
			ਸਥਿਤੀ = SSH2_FX_OK;
		}

	}
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_readdir(uint32_t id)
{
	DIR *dirp;
	ਬਣਤਰ dirent *dp;
	ਅੱਖਰ *ਰਸਤਾ;
	ਪੂਰਨ r, handle;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_ਮੰਜ਼ਿਲ_name(handle), handle);
	dirp = handle_ਮੰਜ਼ਿਲ_dir(handle);
	ਰਸਤਾ = handle_ਮੰਜ਼ਿਲ_name(handle);
	ਜੇ (dirp == ਨਿਰਾ || ਰਸਤਾ == ਨਿਰਾ) {
		send_ਸਥਿਤੀ(id, SSH2_FX_FAILURE);
	} ਨਹੀਂਤਾਂ {
		ਬਣਤਰ stat st;
		ਅੱਖਰ *pathname;
		Stat *stats;
		ਪੂਰਨ nstats = 10, ਗਿਣਤੀ_2 = 0, i;

		stats = xcalloc(nstats, ਆਕਾਰ(Stat));
		ਜਦੋਂ ((dp = readdir(dirp)) != ਨਿਰਾ) {
			ਜੇ (ਗਿਣਤੀ_2 >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, ਆਕਾਰ(Stat));
			}
			xasprintf(&pathname, "%s%s%s", ਰਸਤਾ,
			    strcmp(ਰਸਤਾ, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			ਮੁਕਤ(pathname);
			ਜੇ (r == -1)
				ਜਾਰੀ;
			stat_ਮੰਜ਼ਿਲ_attrib(&st, &(stats[ਗਿਣਤੀ_2].attrib));
			stats[ਗਿਣਤੀ_2].name = xstrdup(dp->d_name);
			stats[ਗਿਣਤੀ_2].long_name = ls_file(dp->d_name, &st,
			    0, 0, ਨਿਰਾ, ਨਿਰਾ);
			ਗਿਣਤੀ_2++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			ਜੇ (ਗਿਣਤੀ_2 == 100)
				ਰੋਕੋ;
		}
		ਜੇ (ਗਿਣਤੀ_2 > 0) {
			send_ਨਾਂ(id, ਗਿਣਤੀ_2, stats);
			ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
				ਮੁਕਤ(stats[i].name);
				ਮੁਕਤ(stats[i].long_name);
			}
		} ਨਹੀਂਤਾਂ {
			send_ਸਥਿਤੀ(id, SSH2_FX_EOF);
		}
		ਮੁਕਤ(stats);
	}
}

ਸਥਿਰ ਖਾਲੀ
process_remove(uint32_t id)
{
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_mkdir(uint32_t id)
{
	Attrib a;
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਬਹੁਲਕ, ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	ਬਹੁਲਕ = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, ਬਹੁਲਕ);
	r = mkdir(name, ਬਹੁਲਕ);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_rmdir(uint32_t id)
{
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_realpath(uint32_t id)
{
	ਅੱਖਰ resolvedname[PATH_MAX];
	ਅੱਖਰ *ਰਸਤਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &ਰਸਤਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (ਰਸਤਾ[0] == '\0') {
		ਮੁਕਤ(ਰਸਤਾ);
		ਰਸਤਾ = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", ਰਸਤਾ);
	ਜੇ (sftp_realpath(ਰਸਤਾ, resolvedname) == ਨਿਰਾ) {
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
	} ਨਹੀਂਤਾਂ {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_ਨਾਂ(id, 1, &s);
	}
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_rename(uint32_t id)
{
	ਅੱਖਰ *oldpath, *newpath;
	ਪੂਰਨ r, ਸਥਿਤੀ;
	ਬਣਤਰ stat sb;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &oldpath, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	ਸਥਿਤੀ = SSH2_FX_FAILURE;
	ਜੇ (lstat(oldpath, &sb) == -1)
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	ਨਹੀਂਤਾਂ ਜੇ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		ਜੇ (link(oldpath, newpath) == -1) {
			ਜੇ (errno == EOPNOTSUPP || errno == ENOSYS
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EXDEV
			    || errno == EXDEV
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#ਜੇ_ਅੰਤ
			    ) {
				ਬਣਤਰ stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				ਜੇ (stat(newpath, &st) == -1) {
					ਜੇ (rename(oldpath, newpath) == -1)
						ਸਥਿਤੀ =
						    errno_ਮੰਜ਼ਿਲ_portable(errno);
					ਨਹੀਂਤਾਂ
						ਸਥਿਤੀ = SSH2_FX_OK;
				}
			} ਨਹੀਂਤਾਂ {
				ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (unlink(oldpath) == -1) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} ਨਹੀਂਤਾਂ
			ਸਥਿਤੀ = SSH2_FX_OK;
	} ਨਹੀਂਤਾਂ ਜੇ (stat(newpath, &sb) == -1) {
		ਜੇ (rename(oldpath, newpath) == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		ਨਹੀਂਤਾਂ
			ਸਥਿਤੀ = SSH2_FX_OK;
	}
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(oldpath);
	ਮੁਕਤ(newpath);
}

ਸਥਿਰ ਖਾਲੀ
process_readlink(uint32_t id)
{
	ਪੂਰਨ r, len;
	ਅੱਖਰ buf[PATH_MAX];
	ਅੱਖਰ *ਰਸਤਾ;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &ਰਸਤਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", ਰਸਤਾ);
	ਜੇ ((len = readlink(ਰਸਤਾ, buf, ਆਕਾਰ(buf) - 1)) == -1)
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
	ਨਹੀਂਤਾਂ {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_ਨਾਂ(id, 1, &s);
	}
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_symlink(uint32_t id)
{
	ਅੱਖਰ *oldpath, *newpath;
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &oldpath, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(oldpath);
	ਮੁਕਤ(newpath);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_posix_rename(uint32_t id)
{
	ਅੱਖਰ *oldpath, *newpath;
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &oldpath, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(oldpath);
	ਮੁਕਤ(newpath);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_statvfs(uint32_t id)
{
	ਅੱਖਰ *ਰਸਤਾ;
	ਬਣਤਰ statvfs st;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &ਰਸਤਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", ਰਸਤਾ);

	ਜੇ (statvfs(ਰਸਤਾ, &st) != 0)
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
	ਨਹੀਂਤਾਂ
		send_statvfs(id, &st);
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_fstatvfs(uint32_t id)
{
	ਪੂਰਨ r, handle, fd;
	ਬਣਤਰ statvfs st;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_ਮੰਜ਼ਿਲ_name(handle), handle);
	ਜੇ ((fd = handle_ਮੰਜ਼ਿਲ_fd(handle)) < 0) {
		send_ਸਥਿਤੀ(id, SSH2_FX_FAILURE);
		ਵਾਪਸ;
	}
	ਜੇ (fstatvfs(fd, &st) != 0)
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
	ਨਹੀਂਤਾਂ
		send_statvfs(id, &st);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_hardlink(uint32_t id)
{
	ਅੱਖਰ *oldpath, *newpath;
	ਪੂਰਨ r, ਸਥਿਤੀ;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &oldpath, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(oldpath);
	ਮੁਕਤ(newpath);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_fsync(uint32_t id)
{
	ਪੂਰਨ handle, fd, r, ਸਥਿਤੀ = SSH2_FX_OP_UNSUPPORTED;

	ਜੇ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_ਮੰਜ਼ਿਲ_name(handle));
	ਜੇ ((fd = handle_ਮੰਜ਼ਿਲ_fd(handle)) < 0)
		ਸਥਿਤੀ = SSH2_FX_NO_SUCH_FILE;
	ਨਹੀਂਤਾਂ ਜੇ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		ਸਥਿਤੀ = (r == -1) ? errno_ਮੰਜ਼ਿਲ_portable(errno) : SSH2_FX_OK;
	}
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	ਅੱਖਰ *name;
	ਪੂਰਨ r, ਸਥਿਤੀ = SSH2_FX_OK;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &name, ਨਿਰਾ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ਮਾਪ) {
		/* nonsensical for links */
		ਸਥਿਤੀ = SSH2_FX_BAD_ਸੁਨੇਹਾ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ਅੱਖਰ buf[64];
		time_t t = a.mtime;

		strftime(buf, ਆਕਾਰ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_ਮੰਜ਼ਿਲ_ts(&a), AT_SYMLINK_NOFOLLOW);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
	ਜੇ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		ਜੇ (r == -1)
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
	}
 ਬਾਹਰਲਾ:
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
	ਮੁਕਤ(name);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_limits(uint32_t id)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;
	uint64_t nfiles = 0;
#ਜੇ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ਬਣਤਰ rlimit rlim;
#ਜੇ_ਅੰਤ

	debug("request %u: limits", id);

#ਜੇ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ਜੇ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#ਜੇ_ਅੰਤ

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED_ਜਵਾਬ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, SFTP_MAX_READ_ਲੰਮਾਈ)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_expand(uint32_t id)
{
	ਅੱਖਰ cwd[PATH_MAX], resolvedname[PATH_MAX];
	ਅੱਖਰ *ਰਸਤਾ, *npath;
	ਪੂਰਨ r;
	Stat s;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &ਰਸਤਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (getcwd(cwd, ਆਕਾਰ(cwd)) == ਨਿਰਾ) {
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug3("request %u: expand, original \"%s\"", id, ਰਸਤਾ);
	ਜੇ (ਰਸਤਾ[0] == '\0') {
		/* empty path */
		ਮੁਕਤ(ਰਸਤਾ);
		ਰਸਤਾ = xstrdup(".");
	} ਨਹੀਂਤਾਂ ਜੇ (*ਰਸਤਾ == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		ਜੇ (strcmp(ਰਸਤਾ, "~") == 0) {
			ਮੁਕਤ(ਰਸਤਾ);
			ਰਸਤਾ = xstrdup(cwd);
		} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਰਸਤਾ, "~/", 2) == 0) {
			npath = xstrdup(ਰਸਤਾ + 2);
			ਮੁਕਤ(ਰਸਤਾ);
			xasprintf(&ਰਸਤਾ, "%s/%s", cwd, npath);
			ਮੁਕਤ(npath);
		} ਨਹੀਂਤਾਂ {
			/* ~user expansions */
			ਜੇ (tilde_expand(ਰਸਤਾ, pw->pw_uid, &npath) != 0) {
				send_ਸਥਿਤੀ_errmsg(id,
				    errno_ਮੰਜ਼ਿਲ_portable(ENOENT), "no such user");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮੁਕਤ(ਰਸਤਾ);
			ਰਸਤਾ = npath;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (*ਰਸਤਾ != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, ਰਸਤਾ);
		ਮੁਕਤ(ਰਸਤਾ);
		ਰਸਤਾ = npath;
	}
	verbose("expand \"%s\"", ਰਸਤਾ);
	ਜੇ (sftp_realpath(ਰਸਤਾ, resolvedname) == ਨਿਰਾ) {
		send_ਸਥਿਤੀ(id, errno_ਮੰਜ਼ਿਲ_portable(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_ਨਾਂ(id, 1, &s);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_copy_ਅੰਕੜੇ(uint32_t id)
{
	u_char buf[64*1024];
	ਪੂਰਨ read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	ਪੂਰਨ r, copy_until_eof, ਸਥਿਤੀ = SSH2_FX_OP_UNSUPPORTED;
	ਮਾਪ_t ret;
	ਬਣਤਰ stat st_read, st_write;

	ਜੇ ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_ਮੰਜ਼ਿਲ_name(read_handle), read_handle,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)read_off, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)read_len,
	    handle_ਮੰਜ਼ਿਲ_name(write_handle), write_handle,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)write_off);

	/* For read length of 0, we read until EOF. */
	ਜੇ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} ਨਹੀਂਤਾਂ
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_ਮੰਜ਼ਿਲ_fd(read_handle);
	write_fd = handle_ਮੰਜ਼ਿਲ_fd(write_handle);
	ਜੇ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(EBADF);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fstat(read_fd, &st_read) != 0) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fstat(write_fd, &st_write) != 0) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (read_handle == write_handle ||
	    !strcmp(handle_ਮੰਜ਼ਿਲ_name(read_handle), handle_ਮੰਜ਼ਿਲ_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_ਮੰਜ਼ਿਲ_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_ਮੰਜ਼ਿਲ_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("read_seek failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((handle_ਮੰਜ਼ਿਲ_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
		error_f("write_seek failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Process the request in chunks. */
	ਜਦੋਂ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(ਆਕਾਰ(buf), read_len);
		read_len -= len;

		ret = atomicio(ਪਠ, read_fd, buf, len);
		ਜੇ (ret == 0 && errno == EPIPE) {
			ਸਥਿਤੀ = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ ਜੇ (ret == 0) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ਰੋਕੋ;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		ਜੇ (ret != len) {
			ਸਥਿਤੀ = errno_ਮੰਜ਼ਿਲ_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ret, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)len,
			    strerror(errno));
			ਰੋਕੋ;
		}
		handle_update_write(write_handle, len);
	}

	ਜੇ (read_len == 0)
		ਸਥਿਤੀ = SSH2_FX_OK;

 ਬਾਹਰਲਾ:
	send_ਸਥਿਤੀ(id, ਸਥਿਤੀ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_home_directory(uint32_t id)
{
	ਅੱਖਰ *username;
	ਬਣਤਰ passwd *user_pw;
	ਪੂਰਨ r;
	Stat s;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &username, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	ਜੇ (username[0] == '\0') {
		user_pw = pw;
	} ਨਹੀਂਤਾਂ ਜੇ ((user_pw = getpwnam(username)) == ਨਿਰਾ) {
		send_ਸਥਿਤੀ(id, SSH2_FX_FAILURE);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_ਨਾਂ(id, 1, &s);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(username);
}

ਸਥਿਰ ਖਾਲੀ
process_extended_get_users_groups_by_id(uint32_t id)
{
	ਬਣਤਰ passwd *user_pw;
	ਬਣਤਰ ਸਮੂਹ *gr;
	ਬਣਤਰ sshbuf *uids, *gids, *usernames, *groupnames, *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;
	u_int n, nusers = 0, ngroups = 0;
	ਅਚਲ ਅੱਖਰ *name;

	ਜੇ ((usernames = sshbuf_new()) == ਨਿਰਾ ||
	    (groupnames = sshbuf_new()) == ਨਿਰਾ ||
	    (ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	ਜਦੋਂ (sshbuf_len(uids) != 0) {
		ਜੇ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ਨਿਰਾ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		ਜੇ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	ਜਦੋਂ (sshbuf_len(gids) != 0) {
		ਜੇ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ਨਿਰਾ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		ਜੇ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED_ਜਵਾਬ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(ਸੁਨੇਹਾ);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
process_extended(uint32_t id)
{
	ਅੱਖਰ *request;
	ਪੂਰਨ r;
	ਅਚਲ ਬਣਤਰ sftp_handler *exthand;

	ਜੇ ((r = sshbuf_get_cstring(iqueue, &request, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");
	ਜੇ ((exthand = extended_handler_byname(request)) == ਨਿਰਾ) {
		error("Unknown extended request \"%.100s\"", request);
		send_ਸਥਿਤੀ(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} ਨਹੀਂਤਾਂ {
		ਜੇ (!request_permitted(exthand))
			send_ਸਥਿਤੀ(id, SSH2_FX_PERMISSION_DENIED);
		ਨਹੀਂਤਾਂ
			exthand->handler(id);
	}
	ਮੁਕਤ(request);
}

/* stolen from ssh-agent */

ਸਥਿਰ ਖਾਲੀ
process(ਖਾਲੀ)
{
	u_int ਸੁਨੇਹਾ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ਅਚਲ u_char *cp;
	ਪੂਰਨ i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	ਜੇ (buf_len < 5)
		ਵਾਪਸ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ਸੁਨੇਹਾ_len = get_u32(cp);
	ਜੇ (ਸੁਨੇਹਾ_len > SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	ਜੇ (buf_len < ਸੁਨੇਹਾ_len + 4)
		ਵਾਪਸ;
	ਜੇ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	ਜੇ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	ਚੋਣ (type) {
	ਹਾਲਤ SSH2_FXP_INIT:
		process_init();
		init_ਪੂਰਾ = 1;
		ਰੋਕੋ;
	ਹਾਲਤ SSH2_FXP_EXTENDED:
		ਜੇ (!init_ਪੂਰਾ)
			fatal("Received extended request before init");
		ਜੇ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ਰੋਕੋ;
	ਮੂਲ:
		ਜੇ (!init_ਪੂਰਾ)
			fatal("Received %u request before init", type);
		ਜੇ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		ਲਈ (i = 0; handlers[i].handler != ਨਿਰਾ; i++) {
			ਜੇ (type == handlers[i].type) {
				ਜੇ (!request_permitted(&handlers[i])) {
					send_ਸਥਿਤੀ(id,
					    SSH2_FX_PERMISSION_DENIED);
				} ਨਹੀਂਤਾਂ {
					handlers[i].handler(id);
				}
				ਰੋਕੋ;
			}
		}
		ਜੇ (handlers[i].handler == ਨਿਰਾ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	ਜੇ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ਜੇ (ਸੁਨੇਹਾ_len < consumed) {
		error("msg_len %u < consumed %u", ਸੁਨੇਹਾ_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	ਜੇ (ਸੁਨੇਹਾ_len > consumed &&
	    (r = sshbuf_consume(iqueue, ਸੁਨੇਹਾ_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
ਖਾਲੀ
sftp_server_cleanup_exit(ਪੂਰਨ i)
{
	ਜੇ (pw != ਨਿਰਾ && client_addr != ਨਿਰਾ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ਸਥਿਰ ਖਾਲੀ
sftp_server_usage(ਖਾਲੀ)
{
	ਬਾਹਰੀ ਅੱਖਰ *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
sftp_server_main(ਪੂਰਨ argc, ਅੱਖਰ **argv, ਬਣਤਰ passwd *user_pw)
{
	ਪੂਰਨ i, r, ਵਿੱਚ, ਬਾਹਰਲਾ, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	ਅੱਖਰ *cp, *homedir = ਨਿਰਾ, uidstr[32], buf[4*4096];
	ਲੰਮਾ ਨਕਾਬ;

	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਅੱਖਰ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	ਜਦੋਂ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'Q':
			ਜੇ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਲਈ (i = 0; handlers[i].handler != ਨਿਰਾ; i++)
				ਲਿਖੋ("%s\n", handlers[i].name);
			ਲਈ (i = 0; extended_handlers[i].handler != ਨਿਰਾ; i++)
				ਲਿਖੋ("%s\n", extended_handlers[i].name);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			readonly = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'e':
			log_stderr = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			log_level = log_level_ਸੰਖਿਆ(optarg);
			ਜੇ (log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ)
				error("Invalid log level \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			log_facility = log_facility_ਸੰਖਿਆ(optarg);
			ਜੇ (log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ)
				error("Invalid log facility \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (ਅੱਖਰ *)ਨਿਰਾ);
			ਮੁਕਤ(cp);
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			ਜੇ (request_allowlist != ਨਿਰਾ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			ਜੇ (request_denylist != ਨਿਰਾ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			errno = 0;
			ਨਕਾਬ = strtol(optarg, &cp, 8);
			ਜੇ (ਨਕਾਬ < 0 || ਨਕਾਬ > 0777 || *cp != '\0' ||
			    cp == optarg || (ਨਕਾਬ == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(ਖਾਲੀ)umask((ਬਹੁਲਕ_t)ਨਕਾਬ);
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
		ਮੂਲ:
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

	ਜੇ ((cp = getenv("SSH_CONNECTION")) != ਨਿਰਾ) {
		client_addr = xstrdup(cp);
		ਜੇ ((cp = strchr(client_addr, ' ')) == ਨਿਰਾ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} ਨਹੀਂਤਾਂ
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	ਵਿੱਚ = STDIN_FILENO;
	ਬਾਹਰਲਾ = STDOUT_FILENO;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	setmode(ਵਿੱਚ, O_ਦੁਆਧਾਰੀ);
	setmode(ਬਾਹਰਲਾ, O_ਦੁਆਧਾਰੀ);
#ਜੇ_ਅੰਤ

	ਜੇ ((iqueue = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((oqueue = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜੇ (homedir != ਨਿਰਾ) {
		ਜੇ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	ਲਈ (;;) {
		ਬਣਤਰ pollfd pfd[2];

		memset(pfd, 0, ਆਕਾਰ pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ਜੇ ((r = sshbuf_check_reserve(iqueue, ਆਕਾਰ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ)) == 0) {
			pfd[0].fd = ਵਿੱਚ;
			pfd[0].events = POLLIN;
		}
		ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_NO_ਬਫਰ_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		ਜੇ (olen > 0) {
			pfd[1].fd = ਬਾਹਰਲਾ;
			pfd[1].events = POLLOUT;
		}

		ਜੇ (poll(pfd, 2, -1) == -1) {
			ਜੇ (errno == EINTR)
				ਜਾਰੀ;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		ਜੇ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = ਪਠ(ਵਿੱਚ, buf, ਆਕਾਰ buf);
			ਜੇ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} ਨਹੀਂਤਾਂ ਜੇ (len == -1) {
				ਜੇ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ਜੇ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ਲਿਖ(ਬਾਹਰਲਾ, sshbuf_ptr(oqueue), olen);
			ਜੇ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} ਨਹੀਂਤਾਂ ਜੇ (len == -1) {
				sftp_server_cleanup_exit(1);
				ਜੇ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ);
		ਜੇ (r == 0)
			process();
		ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_NO_ਬਫਰ_SPACE)
			fatal_fr(r, "reserve");
	}
}
