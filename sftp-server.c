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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/resource.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/statvfs.h>

#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "uidswap.h"

#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "sftp-common.h"

അക്ഷരം *sftp_realpath(സ്ഥിരം അക്ഷരം *, അക്ഷരം *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_സന്ദേശം_LENGTH - 1024)

/* Our verbosity */
സ്ഥിതം LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
സ്ഥിതം ഘടന passwd *pw = ശൂന്യ;
സ്ഥിതം അക്ഷരം *client_addr = ശൂന്യ;

/* input and output queue */
ഘടന sshbuf *iqueue;
ഘടന sshbuf *oqueue;

/* Version of client */
സ്ഥിതം u_int version;

/* SSH2_FXP_INIT received */
സ്ഥിതം പൂർണ്ണസംഖ്യ init_done;

/* Disable writes */
സ്ഥിതം പൂർണ്ണസംഖ്യ readonly;

/* Requests that are allowed/denied */
സ്ഥിതം അക്ഷരം *request_allowlist, *request_denylist;

/* portable attributes, etc. */
തരനിർവചനം ഘടന Stat Stat;

ഘടന Stat {
	അക്ഷരം *name;
	അക്ഷരം *long_name;
	Attrib attrib;
};

/* Packet handlers */
സ്ഥിതം ശൂന്യം process_open(uint32_t id);
സ്ഥിതം ശൂന്യം process_close(uint32_t id);
സ്ഥിതം ശൂന്യം process_read(uint32_t id);
സ്ഥിതം ശൂന്യം process_write(uint32_t id);
സ്ഥിതം ശൂന്യം process_stat(uint32_t id);
സ്ഥിതം ശൂന്യം process_lstat(uint32_t id);
സ്ഥിതം ശൂന്യം process_fstat(uint32_t id);
സ്ഥിതം ശൂന്യം process_setstat(uint32_t id);
സ്ഥിതം ശൂന്യം process_fsetstat(uint32_t id);
സ്ഥിതം ശൂന്യം process_opendir(uint32_t id);
സ്ഥിതം ശൂന്യം process_readdir(uint32_t id);
സ്ഥിതം ശൂന്യം process_remove(uint32_t id);
സ്ഥിതം ശൂന്യം process_mkdir(uint32_t id);
സ്ഥിതം ശൂന്യം process_rmdir(uint32_t id);
സ്ഥിതം ശൂന്യം process_realpath(uint32_t id);
സ്ഥിതം ശൂന്യം process_rename(uint32_t id);
സ്ഥിതം ശൂന്യം process_readlink(uint32_t id);
സ്ഥിതം ശൂന്യം process_symlink(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_posix_rename(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_statvfs(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_fstatvfs(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_hardlink(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_fsync(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_lsetstat(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_limits(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_expand(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_copy_data(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_home_directory(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended_get_users_groups_by_id(uint32_t id);
സ്ഥിതം ശൂന്യം process_extended(uint32_t id);

ഘടന sftp_handler {
	സ്ഥിരം അക്ഷരം *name;	/* user-visible name for fine-grained perms */
	സ്ഥിരം അക്ഷരം *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	ശൂന്യം (*handler)(uint32_t);
	പൂർണ്ണസംഖ്യ does_write;		/* if nonzero, banned for readonly mode */
};

സ്ഥിതം സ്ഥിരം ഘടന sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ശൂന്യ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ശൂന്യ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ശൂന്യ, SSH2_FXP_READ, process_read, 0 },
	{ "write", ശൂന്യ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ശൂന്യ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ശൂന്യ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ശൂന്യ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ശൂന്യ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ശൂന്യ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ശൂന്യ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ശൂന്യ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ശൂന്യ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ശൂന്യ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ശൂന്യ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ശൂന്യ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ശൂന്യ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ശൂന്യ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ശൂന്യ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ശൂന്യ, ശൂന്യ, 0, ശൂന്യ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
സ്ഥിതം സ്ഥിരം ഘടന sftp_handler extended_handlers[] = {
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
	{ ശൂന്യ, ശൂന്യ, 0, ശൂന്യ, 0 }
};

സ്ഥിതം സ്ഥിരം ഘടന sftp_handler *
extended_handler_byname(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; extended_handlers[i].handler != ശൂന്യ; i++) {
		എങ്കിൽ (strcmp(name, extended_handlers[i].ext_name) == 0)
			തിരികെ &extended_handlers[i];
	}
	തിരികെ ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
request_permitted(സ്ഥിരം ഘടന sftp_handler *h)
{
	അക്ഷരം *result;

	എങ്കിൽ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		തിരികെ 0;
	}
	എങ്കിൽ (request_denylist != ശൂന്യ &&
	    ((result = match_list(h->name, request_denylist, ശൂന്യ))) != ശൂന്യ) {
		സ്വതന്ത്രം(result);
		verbose("Refusing denylisted %s request", h->name);
		തിരികെ 0;
	}
	എങ്കിൽ (request_allowlist != ശൂന്യ &&
	    ((result = match_list(h->name, request_allowlist, ശൂന്യ))) != ശൂന്യ) {
		സ്വതന്ത്രം(result);
		debug2("Permitting allowlisted %s request", h->name);
		തിരികെ 1;
	}
	എങ്കിൽ (request_allowlist != ശൂന്യ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		തിരികെ 0;
	}
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
errno_to_portable(പൂർണ്ണസംഖ്യ unixerrno)
{
	പൂർണ്ണസംഖ്യ ret = 0;

	തിരഞ്ഞെടുപ്പ് (unixerrno) {
	അവസ്ഥ 0:
		ret = SSH2_FX_OK;
		നിർത്തുക;
	അവസ്ഥ ENOENT:
	അവസ്ഥ ENOTDIR:
	അവസ്ഥ EBADF:
	അവസ്ഥ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		നിർത്തുക;
	അവസ്ഥ EPERM:
	അവസ്ഥ EACCES:
	അവസ്ഥ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		നിർത്തുക;
	അവസ്ഥ ENAMETOOLONG:
	അവസ്ഥ EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		നിർത്തുക;
	അവസ്ഥ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		ret = SSH2_FX_FAILURE;
		നിർത്തുക;
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
flags_from_portable(പൂർണ്ണസംഖ്യ pflags)
{
	പൂർണ്ണസംഖ്യ flags = 0;

	എങ്കിൽ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} അല്ലെങ്കിൽ എങ്കിൽ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} അല്ലെങ്കിൽ എങ്കിൽ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	എങ്കിൽ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	എങ്കിൽ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	എങ്കിൽ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	എങ്കിൽ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	തിരികെ flags;
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
string_from_portable(പൂർണ്ണസംഖ്യ pflags)
{
	സ്ഥിതം അക്ഷരം ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		എങ്കിൽ (*ret != '\0')			\
			strlcat(ret, ",", വലുപ്പം(ret));	\
		strlcat(ret, str, വലുപ്പം(ret));		\
	}

	എങ്കിൽ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	എങ്കിൽ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	എങ്കിൽ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	എങ്കിൽ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	എങ്കിൽ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	എങ്കിൽ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	തിരികെ ret;
}

/* handle handles */

തരനിർവചനം ഘടന Handle Handle;
ഘടന Handle {
	പൂർണ്ണസംഖ്യ use;
	DIR *dirp;
	പൂർണ്ണസംഖ്യ fd;
	പൂർണ്ണസംഖ്യ flags;
	അക്ഷരം *name;
	uint64_t bytes_read, bytes_write;
	പൂർണ്ണസംഖ്യ next_unused;
};

എണ്ണൽ {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

സ്ഥിതം Handle *handles = ശൂന്യ;
സ്ഥിതം u_int അക്കം_handles = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ first_unused_handle = -1;

സ്ഥിതം ശൂന്യം handle_unused(പൂർണ്ണസംഖ്യ i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_new(പൂർണ്ണസംഖ്യ use, സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ flags, DIR *dirp)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (first_unused_handle == -1) {
		എങ്കിൽ (അക്കം_handles + 1 <= അക്കം_handles)
			തിരികെ -1;
		അക്കം_handles++;
		handles = xreallocarray(handles, അക്കം_handles, വലുപ്പം(Handle));
		handle_unused(അക്കം_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	തിരികെ i;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_is_ok(പൂർണ്ണസംഖ്യ i, പൂർണ്ണസംഖ്യ type)
{
	തിരികെ i >= 0 && (u_int)i < അക്കം_handles && handles[i].use == type;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_to_string(പൂർണ്ണസംഖ്യ handle, u_char **stringp, പൂർണ്ണസംഖ്യ *hlenp)
{
	എങ്കിൽ (stringp == ശൂന്യ || hlenp == ശൂന്യ)
		തിരികെ -1;
	*stringp = xmalloc(വലുപ്പം(int32_t));
	put_u32(*stringp, handle);
	*hlenp = വലുപ്പം(int32_t);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_from_string(സ്ഥിരം u_char *handle, u_int hlen)
{
	പൂർണ്ണസംഖ്യ val;

	എങ്കിൽ (hlen != വലുപ്പം(int32_t))
		തിരികെ -1;
	val = get_u32(handle);
	എങ്കിൽ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		തിരികെ val;
	തിരികെ -1;
}

സ്ഥിതം അക്ഷരം *
handle_to_name(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		തിരികെ handles[handle].name;
	തിരികെ ശൂന്യ;
}

സ്ഥിതം DIR *
handle_to_dir(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_DIR))
		തിരികെ handles[handle].dirp;
	തിരികെ ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_to_fd(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE))
		തിരികെ handles[handle].fd;
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_to_flags(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE))
		തിരികെ handles[handle].flags;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
handle_update_read(പൂർണ്ണസംഖ്യ handle, ssize_t bytes)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

സ്ഥിതം ശൂന്യം
handle_update_write(പൂർണ്ണസംഖ്യ handle, ssize_t bytes)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

സ്ഥിതം uint64_t
handle_bytes_read(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE))
		തിരികെ (handles[handle].bytes_read);
	തിരികെ 0;
}

സ്ഥിതം uint64_t
handle_bytes_write(പൂർണ്ണസംഖ്യ handle)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE))
		തിരികെ (handles[handle].bytes_write);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
handle_close(പൂർണ്ണസംഖ്യ handle)
{
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		സ്വതന്ത്രം(handles[handle].name);
		handle_unused(handle);
	} അല്ലെങ്കിൽ എങ്കിൽ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		സ്വതന്ത്രം(handles[handle].name);
		handle_unused(handle);
	} അല്ലെങ്കിൽ {
		errno = ENOENT;
	}
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
handle_log_close(പൂർണ്ണസംഖ്യ handle, അക്ഷരം *emsg)
{
	എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ശൂന്യ ? "" : emsg, emsg == ശൂന്യ ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} അല്ലെങ്കിൽ {
		logit("%s%sclosedir \"%s\"",
		    emsg == ശൂന്യ ? "" : emsg, emsg == ശൂന്യ ? "" : " ",
		    handle_to_name(handle));
	}
}

സ്ഥിതം ശൂന്യം
handle_log_exit(ശൂന്യം)
{
	u_int i;

	വേണ്ടി (i = 0; i < അക്കം_handles; i++)
		എങ്കിൽ (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_handle(ഘടന sshbuf *queue, പൂർണ്ണസംഖ്യ *hp)
{
	u_char *handle;
	പൂർണ്ണസംഖ്യ r;
	size_t hlen;

	*hp = -1;
	എങ്കിൽ ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		തിരികെ r;
	എങ്കിൽ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	സ്വതന്ത്രം(handle);
	തിരികെ 0;
}

/* send replies */

സ്ഥിതം ശൂന്യം
send_സന്ദേശം(ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
status_to_message(uint32_t status)
{
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം status_messages[] = {
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
	തിരികെ (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

സ്ഥിതം ശൂന്യം
send_status_errmsg(uint32_t id, uint32_t status, സ്ഥിരം അക്ഷരം *errmsg)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	debug3("request %u: sent status %u", id, status);
	എങ്കിൽ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, status)) != 0)
		fatal_fr(r, "compose");
	എങ്കിൽ (version >= 3) {
		എങ്കിൽ ((r = sshbuf_put_cstring(സന്ദേശം, errmsg == ശൂന്യ ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, ശൂന്യ);
}

സ്ഥിതം ശൂന്യം
send_data_or_handle(അക്ഷരം type, uint32_t id, സ്ഥിരം u_char *data, പൂർണ്ണസംഖ്യ dlen)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, type)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
send_data(uint32_t id, സ്ഥിരം u_char *data, പൂർണ്ണസംഖ്യ dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

സ്ഥിതം ശൂന്യം
send_handle(uint32_t id, പൂർണ്ണസംഖ്യ handle)
{
	u_char *string;
	പൂർണ്ണസംഖ്യ hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	സ്വതന്ത്രം(string);
}

സ്ഥിതം ശൂന്യം
send_names(uint32_t id, പൂർണ്ണസംഖ്യ എണ്ണം, സ്ഥിരം Stat *stats)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ i, r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, എണ്ണം)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, എണ്ണം);
	വേണ്ടി (i = 0; i < എണ്ണം; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(സന്ദേശം, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(സന്ദേശം, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
send_attrib(uint32_t id, സ്ഥിരം Attrib *a)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, a)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
send_statvfs(uint32_t id, ഘടന statvfs *st)
{
	ഘടന sshbuf *സന്ദേശം;
	uint64_t flag;
	പൂർണ്ണസംഖ്യ r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, flag)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
compose_extension(ഘടന sshbuf *സന്ദേശം, സ്ഥിരം അക്ഷരം *name, സ്ഥിരം അക്ഷരം *ver)
{
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം ഘടന sftp_handler *exthnd;

	എങ്കിൽ ((exthnd = extended_handler_byname(name)) == ശൂന്യ)
		fatal_f("internal error: no handler for %s", name);
	എങ്കിൽ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		തിരികെ 0;
	}
	എങ്കിൽ ((r = sshbuf_put_cstring(സന്ദേശം, name)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	തിരികെ 0;
}

/* parse incoming */

സ്ഥിതം ശൂന്യം
process_init(ശൂന്യം)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(സന്ദേശം, "posix-rename@openssh.com", "1");
	compose_extension(സന്ദേശം, "statvfs@openssh.com", "2");
	compose_extension(സന്ദേശം, "fstatvfs@openssh.com", "2");
	compose_extension(സന്ദേശം, "hardlink@openssh.com", "1");
	compose_extension(സന്ദേശം, "fsync@openssh.com", "1");
	compose_extension(സന്ദേശം, "lsetstat@openssh.com", "1");
	compose_extension(സന്ദേശം, "limits@openssh.com", "1");
	compose_extension(സന്ദേശം, "expand-path@openssh.com", "1");
	compose_extension(സന്ദേശം, "copy-data", "1");
	compose_extension(സന്ദേശം, "home-directory", "1");
	compose_extension(സന്ദേശം, "users-groups-by-id@openssh.com", "1");

	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	എങ്കിൽ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} അല്ലെങ്കിൽ {
		fd = open(name, flags, mode);
		എങ്കിൽ (fd == -1) {
			status = errno_to_portable(errno);
		} അല്ലെങ്കിൽ {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ശൂന്യ);
			എങ്കിൽ (handle < 0) {
				close(fd);
			} അല്ലെങ്കിൽ {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	എങ്കിൽ (status != SSH2_FX_OK)
		send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_close(uint32_t id)
{
	പൂർണ്ണസംഖ്യ r, handle, ret, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ശൂന്യ);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

സ്ഥിതം ശൂന്യം
process_read(uint32_t id)
{
	സ്ഥിതം u_char *buf;
	സ്ഥിതം size_t buflen;
	uint32_t len;
	പൂർണ്ണസംഖ്യ r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	എങ്കിൽ ((fd = handle_to_fd(handle)) == -1)
		പോകുക out;
	എങ്കിൽ (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	എങ്കിൽ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		എങ്കിൽ ((buf = realloc(buf, len)) == ശൂന്യ)
			fatal_f("realloc failed");
		buflen = len;
	}
	എങ്കിൽ (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ ((ret = പഠ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (ret == 0) {
		status = SSH2_FX_EOF;
		പോകുക out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	എങ്കിൽ (status != SSH2_FX_OK)
		send_status(id, status);
}

സ്ഥിതം ശൂന്യം
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	പൂർണ്ണസംഖ്യ r, handle, fd, ret, status;
	u_char *data;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	എങ്കിൽ (fd < 0)
		status = SSH2_FX_FAILURE;
	അല്ലെങ്കിൽ {
		എങ്കിൽ (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} അല്ലെങ്കിൽ {
/* XXX ATOMICIO ? */
			ret = ലിഖ(fd, data, len);
			എങ്കിൽ (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} അല്ലെങ്കിൽ എങ്കിൽ ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} അല്ലെങ്കിൽ {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	സ്വതന്ത്രം(data);
}

സ്ഥിതം ശൂന്യം
process_do_stat(uint32_t id, പൂർണ്ണസംഖ്യ do_lstat)
{
	Attrib a;
	ഘടന stat st;
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	എങ്കിൽ (r == -1) {
		status = errno_to_portable(errno);
	} അല്ലെങ്കിൽ {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	എങ്കിൽ (status != SSH2_FX_OK)
		send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

സ്ഥിതം ശൂന്യം
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

സ്ഥിതം ശൂന്യം
process_fstat(uint32_t id)
{
	Attrib a;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ fd, r, handle, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	എങ്കിൽ (fd >= 0) {
		r = fstat(fd, &st);
		എങ്കിൽ (r == -1) {
			status = errno_to_portable(errno);
		} അല്ലെങ്കിൽ {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	എങ്കിൽ (status != SSH2_FX_OK)
		send_status(id, status);
}

സ്ഥിതം ഘടന timeval *
attrib_to_tv(സ്ഥിരം Attrib *a)
{
	സ്ഥിതം ഘടന timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	തിരികെ tv;
}

സ്ഥിതം ഘടന timespec *
attrib_to_ts(സ്ഥിരം Attrib *a)
{
	സ്ഥിതം ഘടന timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	തിരികെ ts;
}

സ്ഥിതം ശൂന്യം
process_setstat(uint32_t id)
{
	Attrib a;
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, status = SSH2_FX_OK;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		അക്ഷരം buf[64];
		time_t t = a.mtime;

		strftime(buf, വലുപ്പം(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_fsetstat(uint32_t id)
{
	Attrib a;
	പൂർണ്ണസംഖ്യ handle, fd, r;
	പൂർണ്ണസംഖ്യ status = SSH2_FX_OK;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	എങ്കിൽ (fd < 0)
		status = SSH2_FX_FAILURE;
	അല്ലെങ്കിൽ {
		അക്ഷരം *name = handle_to_name(handle);

		എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			എങ്കിൽ (r == -1)
				status = errno_to_portable(errno);
		}
		എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#അല്ലെങ്കിൽ
			r = chmod(name, a.perm & 07777);
#endif
			എങ്കിൽ (r == -1)
				status = errno_to_portable(errno);
		}
		എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			അക്ഷരം buf[64];
			time_t t = a.mtime;

			strftime(buf, വലുപ്പം(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#അല്ലെങ്കിൽ
			r = utimes(name, attrib_to_tv(&a));
#endif
			എങ്കിൽ (r == -1)
				status = errno_to_portable(errno);
		}
		എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#അല്ലെങ്കിൽ
			r = chown(name, a.uid, a.gid);
#endif
			എങ്കിൽ (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

സ്ഥിതം ശൂന്യം
process_opendir(uint32_t id)
{
	DIR *dirp = ശൂന്യ;
	അക്ഷരം *path;
	പൂർണ്ണസംഖ്യ r, handle, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &path, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	എങ്കിൽ (dirp == ശൂന്യ) {
		status = errno_to_portable(errno);
	} അല്ലെങ്കിൽ {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		എങ്കിൽ (handle < 0) {
			closedir(dirp);
		} അല്ലെങ്കിൽ {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	എങ്കിൽ (status != SSH2_FX_OK)
		send_status(id, status);
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
process_readdir(uint32_t id)
{
	DIR *dirp;
	ഘടന dirent *dp;
	അക്ഷരം *path;
	പൂർണ്ണസംഖ്യ r, handle;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	എങ്കിൽ (dirp == ശൂന്യ || path == ശൂന്യ) {
		send_status(id, SSH2_FX_FAILURE);
	} അല്ലെങ്കിൽ {
		ഘടന stat st;
		അക്ഷരം *pathname;
		Stat *stats;
		പൂർണ്ണസംഖ്യ nstats = 10, എണ്ണം = 0, i;

		stats = xcalloc(nstats, വലുപ്പം(Stat));
		ആകുമ്പോൾ ((dp = readdir(dirp)) != ശൂന്യ) {
			എങ്കിൽ (എണ്ണം >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, വലുപ്പം(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			സ്വതന്ത്രം(pathname);
			എങ്കിൽ (r == -1)
				തുടരുക;
			stat_to_attrib(&st, &(stats[എണ്ണം].attrib));
			stats[എണ്ണം].name = xstrdup(dp->d_name);
			stats[എണ്ണം].long_name = ls_file(dp->d_name, &st,
			    0, 0, ശൂന്യ, ശൂന്യ);
			എണ്ണം++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			എങ്കിൽ (എണ്ണം == 100)
				നിർത്തുക;
		}
		എങ്കിൽ (എണ്ണം > 0) {
			send_names(id, എണ്ണം, stats);
			വേണ്ടി (i = 0; i < എണ്ണം; i++) {
				സ്വതന്ത്രം(stats[i].name);
				സ്വതന്ത്രം(stats[i].long_name);
			}
		} അല്ലെങ്കിൽ {
			send_status(id, SSH2_FX_EOF);
		}
		സ്വതന്ത്രം(stats);
	}
}

സ്ഥിതം ശൂന്യം
process_remove(uint32_t id)
{
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_mkdir(uint32_t id)
{
	Attrib a;
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, mode, status = SSH2_FX_FAILURE;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_rmdir(uint32_t id)
{
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, status;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_realpath(uint32_t id)
{
	അക്ഷരം resolvedname[PATH_MAX];
	അക്ഷരം *path;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &path, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (path[0] == '\0') {
		സ്വതന്ത്രം(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	എങ്കിൽ (sftp_realpath(path, resolvedname) == ശൂന്യ) {
		send_status(id, errno_to_portable(errno));
	} അല്ലെങ്കിൽ {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
process_rename(uint32_t id)
{
	അക്ഷരം *oldpath, *newpath;
	പൂർണ്ണസംഖ്യ r, status;
	ഘടന stat sb;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &oldpath, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	എങ്കിൽ (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	അല്ലെങ്കിൽ എങ്കിൽ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		എങ്കിൽ (link(oldpath, newpath) == -1) {
			എങ്കിൽ (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				ഘടന stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				എങ്കിൽ (stat(newpath, &st) == -1) {
					എങ്കിൽ (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					അല്ലെങ്കിൽ
						status = SSH2_FX_OK;
				}
			} അല്ലെങ്കിൽ {
				status = errno_to_portable(errno);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} അല്ലെങ്കിൽ
			status = SSH2_FX_OK;
	} അല്ലെങ്കിൽ എങ്കിൽ (stat(newpath, &sb) == -1) {
		എങ്കിൽ (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		അല്ലെങ്കിൽ
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	സ്വതന്ത്രം(oldpath);
	സ്വതന്ത്രം(newpath);
}

സ്ഥിതം ശൂന്യം
process_readlink(uint32_t id)
{
	പൂർണ്ണസംഖ്യ r, len;
	അക്ഷരം buf[PATH_MAX];
	അക്ഷരം *path;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &path, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	എങ്കിൽ ((len = readlink(path, buf, വലുപ്പം(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	അല്ലെങ്കിൽ {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
process_symlink(uint32_t id)
{
	അക്ഷരം *oldpath, *newpath;
	പൂർണ്ണസംഖ്യ r, status;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &oldpath, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(oldpath);
	സ്വതന്ത്രം(newpath);
}

സ്ഥിതം ശൂന്യം
process_extended_posix_rename(uint32_t id)
{
	അക്ഷരം *oldpath, *newpath;
	പൂർണ്ണസംഖ്യ r, status;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &oldpath, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(oldpath);
	സ്വതന്ത്രം(newpath);
}

സ്ഥിതം ശൂന്യം
process_extended_statvfs(uint32_t id)
{
	അക്ഷരം *path;
	ഘടന statvfs st;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &path, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	എങ്കിൽ (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	അല്ലെങ്കിൽ
		send_statvfs(id, &st);
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
process_extended_fstatvfs(uint32_t id)
{
	പൂർണ്ണസംഖ്യ r, handle, fd;
	ഘടന statvfs st;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	എങ്കിൽ ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		തിരികെ;
	}
	എങ്കിൽ (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	അല്ലെങ്കിൽ
		send_statvfs(id, &st);
}

സ്ഥിതം ശൂന്യം
process_extended_hardlink(uint32_t id)
{
	അക്ഷരം *oldpath, *newpath;
	പൂർണ്ണസംഖ്യ r, status;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &oldpath, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	സ്വതന്ത്രം(oldpath);
	സ്വതന്ത്രം(newpath);
}

സ്ഥിതം ശൂന്യം
process_extended_fsync(uint32_t id)
{
	പൂർണ്ണസംഖ്യ handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	എങ്കിൽ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	എങ്കിൽ ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	അല്ലെങ്കിൽ എങ്കിൽ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

സ്ഥിതം ശൂന്യം
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	അക്ഷരം *name;
	പൂർണ്ണസംഖ്യ r, status = SSH2_FX_OK;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &name, ശൂന്യ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		പോകുക out;
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		അക്ഷരം buf[64];
		time_t t = a.mtime;

		strftime(buf, വലുപ്പം(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
	എങ്കിൽ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		എങ്കിൽ (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	സ്വതന്ത്രം(name);
}

സ്ഥിതം ശൂന്യം
process_extended_limits(uint32_t id)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;
	uint64_t nfiles = 0;
#എങ്കിൽ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ഘടന rlimit rlim;
#endif

	debug("request %u: limits", id);

#എങ്കിൽ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	എങ്കിൽ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(സന്ദേശം, SFTP_MAX_സന്ദേശം_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(സന്ദേശം, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(സന്ദേശം, SFTP_MAX_സന്ദേശം_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(സന്ദേശം, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
process_extended_expand(uint32_t id)
{
	അക്ഷരം cwd[PATH_MAX], resolvedname[PATH_MAX];
	അക്ഷരം *path, *npath;
	പൂർണ്ണസംഖ്യ r;
	Stat s;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &path, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (getcwd(cwd, വലുപ്പം(cwd)) == ശൂന്യ) {
		send_status(id, errno_to_portable(errno));
		പോകുക out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	എങ്കിൽ (path[0] == '\0') {
		/* empty path */
		സ്വതന്ത്രം(path);
		path = xstrdup(".");
	} അല്ലെങ്കിൽ എങ്കിൽ (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		എങ്കിൽ (strcmp(path, "~") == 0) {
			സ്വതന്ത്രം(path);
			path = xstrdup(cwd);
		} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			സ്വതന്ത്രം(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			സ്വതന്ത്രം(npath);
		} അല്ലെങ്കിൽ {
			/* ~user expansions */
			എങ്കിൽ (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				പോകുക out;
			}
			സ്വതന്ത്രം(path);
			path = npath;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		സ്വതന്ത്രം(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	എങ്കിൽ (sftp_realpath(path, resolvedname) == ശൂന്യ) {
		send_status(id, errno_to_portable(errno));
		പോകുക out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	പൂർണ്ണസംഖ്യ read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	പൂർണ്ണസംഖ്യ r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	ഘടന stat st_read, st_write;

	എങ്കിൽ ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	എങ്കിൽ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} അല്ലെങ്കിൽ
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	എങ്കിൽ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		പോകുക out;
	}
	എങ്കിൽ (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ (read_handle == write_handle ||
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
		പോകുക out;
	}

	എങ്കിൽ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		പോകുക out;
	}

	എങ്കിൽ ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		പോകുക out;
	}

	/* Process the request in chunks. */
	ആകുമ്പോൾ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(വലുപ്പം(buf), read_len);
		read_len -= len;

		ret = atomicio(പഠ, read_fd, buf, len);
		എങ്കിൽ (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			നിർത്തുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			നിർത്തുക;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		എങ്കിൽ (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			നിർത്തുക;
		}
		handle_update_write(write_handle, len);
	}

	എങ്കിൽ (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

സ്ഥിതം ശൂന്യം
process_extended_home_directory(uint32_t id)
{
	അക്ഷരം *username;
	ഘടന passwd *user_pw;
	പൂർണ്ണസംഖ്യ r;
	Stat s;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &username, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	എങ്കിൽ (username[0] == '\0') {
		user_pw = pw;
	} അല്ലെങ്കിൽ എങ്കിൽ ((user_pw = getpwnam(username)) == ശൂന്യ) {
		send_status(id, SSH2_FX_FAILURE);
		പോകുക out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	സ്വതന്ത്രം(username);
}

സ്ഥിതം ശൂന്യം
process_extended_get_users_groups_by_id(uint32_t id)
{
	ഘടന passwd *user_pw;
	ഘടന group *gr;
	ഘടന sshbuf *uids, *gids, *usernames, *groupnames, *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;
	u_int n, nusers = 0, ngroups = 0;
	സ്ഥിരം അക്ഷരം *name;

	എങ്കിൽ ((usernames = sshbuf_new()) == ശൂന്യ ||
	    (groupnames = sshbuf_new()) == ശൂന്യ ||
	    (സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	ആകുമ്പോൾ (sshbuf_len(uids) != 0) {
		എങ്കിൽ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ശൂന്യ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		എങ്കിൽ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	ആകുമ്പോൾ (sshbuf_len(gids) != 0) {
		എങ്കിൽ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ശൂന്യ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		എങ്കിൽ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(സന്ദേശം);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
process_extended(uint32_t id)
{
	അക്ഷരം *request;
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം ഘടന sftp_handler *exthand;

	എങ്കിൽ ((r = sshbuf_get_cstring(iqueue, &request, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ ((exthand = extended_handler_byname(request)) == ശൂന്യ) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		അല്ലെങ്കിൽ
			exthand->handler(id);
	}
	സ്വതന്ത്രം(request);
}

/* stolen from ssh-agent */

സ്ഥിതം ശൂന്യം
process(ശൂന്യം)
{
	u_int സന്ദേശം_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	സ്ഥിരം u_char *cp;
	പൂർണ്ണസംഖ്യ i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	എങ്കിൽ (buf_len < 5)
		തിരികെ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	സന്ദേശം_len = get_u32(cp);
	എങ്കിൽ (സന്ദേശം_len > SFTP_MAX_സന്ദേശം_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	എങ്കിൽ (buf_len < സന്ദേശം_len + 4)
		തിരികെ;
	എങ്കിൽ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	എങ്കിൽ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		നിർത്തുക;
	അവസ്ഥ SSH2_FXP_EXTENDED:
		എങ്കിൽ (!init_done)
			fatal("Received extended request before init");
		എങ്കിൽ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		എങ്കിൽ (!init_done)
			fatal("Received %u request before init", type);
		എങ്കിൽ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		വേണ്ടി (i = 0; handlers[i].handler != ശൂന്യ; i++) {
			എങ്കിൽ (type == handlers[i].type) {
				എങ്കിൽ (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} അല്ലെങ്കിൽ {
					handlers[i].handler(id);
				}
				നിർത്തുക;
			}
		}
		എങ്കിൽ (handlers[i].handler == ശൂന്യ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	എങ്കിൽ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	എങ്കിൽ (സന്ദേശം_len < consumed) {
		error("msg_len %u < consumed %u", സന്ദേശം_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	എങ്കിൽ (സന്ദേശം_len > consumed &&
	    (r = sshbuf_consume(iqueue, സന്ദേശം_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
ശൂന്യം
sftp_server_cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	എങ്കിൽ (pw != ശൂന്യ && client_addr != ശൂന്യ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

സ്ഥിതം ശൂന്യം
sftp_server_usage(ശൂന്യം)
{
	ബാഹ്യ അക്ഷരം *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

പൂർണ്ണസംഖ്യ
sftp_server_main(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, ഘടന passwd *user_pw)
{
	പൂർണ്ണസംഖ്യ i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	അക്ഷരം *cp, *homedir = ശൂന്യ, uidstr[32], buf[4*4096];
	long mask;

	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ അക്ഷരം *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	ആകുമ്പോൾ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'Q':
			എങ്കിൽ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			വേണ്ടി (i = 0; handlers[i].handler != ശൂന്യ; i++)
				printf("%s\n", handlers[i].name);
			വേണ്ടി (i = 0; extended_handlers[i].handler != ശൂന്യ; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			നിർത്തുക;
		അവസ്ഥ 'R':
			readonly = 1;
			നിർത്തുക;
		അവസ്ഥ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			നിർത്തുക;
		അവസ്ഥ 'e':
			log_stderr = 1;
			നിർത്തുക;
		അവസ്ഥ 'l':
			log_level = log_level_സംഖ്യ(optarg);
			എങ്കിൽ (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'f':
			log_facility = log_facility_സംഖ്യ(optarg);
			എങ്കിൽ (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (അക്ഷരം *)ശൂന്യ);
			സ്വതന്ത്രം(cp);
			നിർത്തുക;
		അവസ്ഥ 'p':
			എങ്കിൽ (request_allowlist != ശൂന്യ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'P':
			എങ്കിൽ (request_denylist != ശൂന്യ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			എങ്കിൽ (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(ശൂന്യം)umask((mode_t)mask);
			നിർത്തുക;
		അവസ്ഥ 'h':
		സ്ഥിരസ്ഥിതി:
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

	എങ്കിൽ ((cp = getenv("SSH_CONNECTION")) != ശൂന്യ) {
		client_addr = xstrdup(cp);
		എങ്കിൽ ((cp = strchr(client_addr, ' ')) == ശൂന്യ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} അല്ലെങ്കിൽ
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_ദ്വിമാന);
	setmode(out, O_ദ്വിമാന);
#endif

	എങ്കിൽ ((iqueue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((oqueue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	എങ്കിൽ (homedir != ശൂന്യ) {
		എങ്കിൽ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	വേണ്ടി (;;) {
		ഘടന pollfd pfd[2];

		memset(pfd, 0, വലുപ്പം pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		എങ്കിൽ ((r = sshbuf_check_reserve(iqueue, വലുപ്പം(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_സന്ദേശം_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		എങ്കിൽ (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		എങ്കിൽ (poll(pfd, 2, -1) == -1) {
			എങ്കിൽ (errno == EINTR)
				തുടരുക;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		എങ്കിൽ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = പഠ(in, buf, വലുപ്പം buf);
			എങ്കിൽ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} അല്ലെങ്കിൽ എങ്കിൽ (len == -1) {
				എങ്കിൽ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		എങ്കിൽ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ലിഖ(out, sshbuf_ptr(oqueue), olen);
			എങ്കിൽ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} അല്ലെങ്കിൽ എങ്കിൽ (len == -1) {
				sftp_server_cleanup_exit(1);
				എങ്കിൽ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_സന്ദേശം_LENGTH);
		എങ്കിൽ (r == 0)
			process();
		അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
