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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/resource.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/statvfs.h>

#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "uidswap.h"

#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "sftp-common.h"

અક્ષર *sftp_realpath(અચલ અક્ષર *, અક્ષર *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_સંદેશ_LENGTH - 1024)

/* Our verbosity */
સ્થિર LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
સ્થિર સંરચના passwd *pw = ખાલી;
સ્થિર અક્ષર *client_addr = ખાલી;

/* input and output queue */
સંરચના sshbuf *iqueue;
સંરચના sshbuf *oqueue;

/* Version of client */
સ્થિર u_int version;

/* SSH2_FXP_INIT received */
સ્થિર પૂર્ણાંક init_done;

/* Disable writes */
સ્થિર પૂર્ણાંક readonly;

/* Requests that are allowed/denied */
સ્થિર અક્ષર *request_allowlist, *request_denylist;

/* portable attributes, etc. */
પ્રકારવ્યાખ્યા સંરચના Stat Stat;

સંરચના Stat {
	અક્ષર *name;
	અક્ષર *long_name;
	Attrib attrib;
};

/* Packet handlers */
સ્થિર શૂન્ય process_open(uint32_t id);
સ્થિર શૂન્ય process_close(uint32_t id);
સ્થિર શૂન્ય process_read(uint32_t id);
સ્થિર શૂન્ય process_write(uint32_t id);
સ્થિર શૂન્ય process_stat(uint32_t id);
સ્થિર શૂન્ય process_lstat(uint32_t id);
સ્થિર શૂન્ય process_fstat(uint32_t id);
સ્થિર શૂન્ય process_setstat(uint32_t id);
સ્થિર શૂન્ય process_fsetstat(uint32_t id);
સ્થિર શૂન્ય process_opendir(uint32_t id);
સ્થિર શૂન્ય process_readdir(uint32_t id);
સ્થિર શૂન્ય process_remove(uint32_t id);
સ્થિર શૂન્ય process_mkdir(uint32_t id);
સ્થિર શૂન્ય process_rmdir(uint32_t id);
સ્થિર શૂન્ય process_realpath(uint32_t id);
સ્થિર શૂન્ય process_rename(uint32_t id);
સ્થિર શૂન્ય process_readlink(uint32_t id);
સ્થિર શૂન્ય process_symlink(uint32_t id);
સ્થિર શૂન્ય process_extended_posix_rename(uint32_t id);
સ્થિર શૂન્ય process_extended_statvfs(uint32_t id);
સ્થિર શૂન્ય process_extended_fstatvfs(uint32_t id);
સ્થિર શૂન્ય process_extended_hardlink(uint32_t id);
સ્થિર શૂન્ય process_extended_fsync(uint32_t id);
સ્થિર શૂન્ય process_extended_lsetstat(uint32_t id);
સ્થિર શૂન્ય process_extended_limits(uint32_t id);
સ્થિર શૂન્ય process_extended_expand(uint32_t id);
સ્થિર શૂન્ય process_extended_copy_data(uint32_t id);
સ્થિર શૂન્ય process_extended_home_directory(uint32_t id);
સ્થિર શૂન્ય process_extended_get_users_groups_by_id(uint32_t id);
સ્થિર શૂન્ય process_extended(uint32_t id);

સંરચના sftp_handler {
	અચલ અક્ષર *name;	/* user-visible name for fine-grained perms */
	અચલ અક્ષર *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	શૂન્ય (*handler)(uint32_t);
	પૂર્ણાંક does_write;		/* if nonzero, banned for readonly mode */
};

સ્થિર અચલ સંરચના sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ખાલી, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ખાલી, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ખાલી, SSH2_FXP_READ, process_read, 0 },
	{ "write", ખાલી, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ખાલી, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ખાલી, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ખાલી, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ખાલી, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ખાલી, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ખાલી, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ખાલી, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ખાલી, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ખાલી, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ખાલી, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ખાલી, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ખાલી, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ખાલી, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ખાલી, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ખાલી, ખાલી, 0, ખાલી, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
સ્થિર અચલ સંરચના sftp_handler extended_handlers[] = {
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
	{ ખાલી, ખાલી, 0, ખાલી, 0 }
};

સ્થિર અચલ સંરચના sftp_handler *
extended_handler_byname(અચલ અક્ષર *name)
{
	પૂર્ણાંક i;

	માટે (i = 0; extended_handlers[i].handler != ખાલી; i++) {
		જો (strcmp(name, extended_handlers[i].ext_name) == 0)
			પાછા &extended_handlers[i];
	}
	પાછા ખાલી;
}

સ્થિર પૂર્ણાંક
request_permitted(અચલ સંરચના sftp_handler *h)
{
	અક્ષર *result;

	જો (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		પાછા 0;
	}
	જો (request_denylist != ખાલી &&
	    ((result = match_list(h->name, request_denylist, ખાલી))) != ખાલી) {
		મુક્ત(result);
		verbose("Refusing denylisted %s request", h->name);
		પાછા 0;
	}
	જો (request_allowlist != ખાલી &&
	    ((result = match_list(h->name, request_allowlist, ખાલી))) != ખાલી) {
		મુક્ત(result);
		debug2("Permitting allowlisted %s request", h->name);
		પાછા 1;
	}
	જો (request_allowlist != ખાલી) {
		verbose("Refusing non-allowlisted %s request", h->name);
		પાછા 0;
	}
	પાછા 1;
}

સ્થિર પૂર્ણાંક
errno_to_portable(પૂર્ણાંક unixerrno)
{
	પૂર્ણાંક ret = 0;

	પસંદગી (unixerrno) {
	સ્થિતિ 0:
		ret = SSH2_FX_OK;
		તોડો;
	સ્થિતિ ENOENT:
	સ્થિતિ ENOTDIR:
	સ્થિતિ EBADF:
	સ્થિતિ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		તોડો;
	સ્થિતિ EPERM:
	સ્થિતિ EACCES:
	સ્થિતિ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		તોડો;
	સ્થિતિ ENAMETOOLONG:
	સ્થિતિ EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		તોડો;
	સ્થિતિ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		તોડો;
	મૂળભૂત:
		ret = SSH2_FX_FAILURE;
		તોડો;
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
flags_from_portable(પૂર્ણાંક pflags)
{
	પૂર્ણાંક flags = 0;

	જો ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} નહીંતર જો (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} નહીંતર જો (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	જો (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	જો (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	જો (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	જો (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	પાછા flags;
}

સ્થિર અચલ અક્ષર *
string_from_portable(પૂર્ણાંક pflags)
{
	સ્થિર અક્ષર ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		જો (*ret != '\0')			\
			strlcat(ret, ",", કદ(ret));	\
		strlcat(ret, str, કદ(ret));		\
	}

	જો (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	જો (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	જો (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	જો (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	જો (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	જો (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	પાછા ret;
}

/* handle handles */

પ્રકારવ્યાખ્યા સંરચના Handle Handle;
સંરચના Handle {
	પૂર્ણાંક use;
	DIR *dirp;
	પૂર્ણાંક fd;
	પૂર્ણાંક flags;
	અક્ષર *name;
	uint64_t bytes_read, bytes_write;
	પૂર્ણાંક next_unused;
};

ગણના {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

સ્થિર Handle *handles = ખાલી;
સ્થિર u_int અંક_handles = 0;
સ્થિર પૂર્ણાંક first_unused_handle = -1;

સ્થિર શૂન્ય handle_unused(પૂર્ણાંક i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

સ્થિર પૂર્ણાંક
handle_new(પૂર્ણાંક use, અચલ અક્ષર *name, પૂર્ણાંક fd, પૂર્ણાંક flags, DIR *dirp)
{
	પૂર્ણાંક i;

	જો (first_unused_handle == -1) {
		જો (અંક_handles + 1 <= અંક_handles)
			પાછા -1;
		અંક_handles++;
		handles = xreallocarray(handles, અંક_handles, કદ(Handle));
		handle_unused(અંક_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	પાછા i;
}

સ્થિર પૂર્ણાંક
handle_is_ok(પૂર્ણાંક i, પૂર્ણાંક type)
{
	પાછા i >= 0 && (u_int)i < અંક_handles && handles[i].use == type;
}

સ્થિર પૂર્ણાંક
handle_to_string(પૂર્ણાંક handle, u_char **stringp, પૂર્ણાંક *hlenp)
{
	જો (stringp == ખાલી || hlenp == ખાલી)
		પાછા -1;
	*stringp = xmalloc(કદ(int32_t));
	put_u32(*stringp, handle);
	*hlenp = કદ(int32_t);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
handle_from_string(અચલ u_char *handle, u_int hlen)
{
	પૂર્ણાંક val;

	જો (hlen != કદ(int32_t))
		પાછા -1;
	val = get_u32(handle);
	જો (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		પાછા val;
	પાછા -1;
}

સ્થિર અક્ષર *
handle_to_name(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		પાછા handles[handle].name;
	પાછા ખાલી;
}

સ્થિર DIR *
handle_to_dir(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_DIR))
		પાછા handles[handle].dirp;
	પાછા ખાલી;
}

સ્થિર પૂર્ણાંક
handle_to_fd(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_FILE))
		પાછા handles[handle].fd;
	પાછા -1;
}

સ્થિર પૂર્ણાંક
handle_to_flags(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_FILE))
		પાછા handles[handle].flags;
	પાછા 0;
}

સ્થિર શૂન્ય
handle_update_read(પૂર્ણાંક handle, ssize_t bytes)
{
	જો (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

સ્થિર શૂન્ય
handle_update_write(પૂર્ણાંક handle, ssize_t bytes)
{
	જો (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

સ્થિર uint64_t
handle_bytes_read(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_FILE))
		પાછા (handles[handle].bytes_read);
	પાછા 0;
}

સ્થિર uint64_t
handle_bytes_write(પૂર્ણાંક handle)
{
	જો (handle_is_ok(handle, HANDLE_FILE))
		પાછા (handles[handle].bytes_write);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
handle_close(પૂર્ણાંક handle)
{
	પૂર્ણાંક ret = -1;

	જો (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		મુક્ત(handles[handle].name);
		handle_unused(handle);
	} નહીંતર જો (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		મુક્ત(handles[handle].name);
		handle_unused(handle);
	} નહીંતર {
		errno = ENOENT;
	}
	પાછા ret;
}

સ્થિર શૂન્ય
handle_log_close(પૂર્ણાંક handle, અક્ષર *emsg)
{
	જો (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ખાલી ? "" : emsg, emsg == ખાલી ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} નહીંતર {
		logit("%s%sclosedir \"%s\"",
		    emsg == ખાલી ? "" : emsg, emsg == ખાલી ? "" : " ",
		    handle_to_name(handle));
	}
}

સ્થિર શૂન્ય
handle_log_exit(શૂન્ય)
{
	u_int i;

	માટે (i = 0; i < અંક_handles; i++)
		જો (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

સ્થિર પૂર્ણાંક
get_handle(સંરચના sshbuf *queue, પૂર્ણાંક *hp)
{
	u_char *handle;
	પૂર્ણાંક r;
	size_t hlen;

	*hp = -1;
	જો ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		પાછા r;
	જો (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	મુક્ત(handle);
	પાછા 0;
}

/* send replies */

સ્થિર શૂન્ય
send_સંદેશ(સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

સ્થિર અચલ અક્ષર *
status_to_message(uint32_t status)
{
	સ્થિર અચલ અક્ષર * અચલ status_messages[] = {
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
	પાછા (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

સ્થિર શૂન્ય
send_status_errmsg(uint32_t id, uint32_t status, અચલ અક્ષર *errmsg)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	debug3("request %u: sent status %u", id, status);
	જો (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, status)) != 0)
		fatal_fr(r, "compose");
	જો (version >= 3) {
		જો ((r = sshbuf_put_cstring(સંદેશ, errmsg == ખાલી ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, ખાલી);
}

સ્થિર શૂન્ય
send_data_or_handle(અક્ષર type, uint32_t id, અચલ u_char *data, પૂર્ણાંક dlen)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, type)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
send_data(uint32_t id, અચલ u_char *data, પૂર્ણાંક dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

સ્થિર શૂન્ય
send_handle(uint32_t id, પૂર્ણાંક handle)
{
	u_char *string;
	પૂર્ણાંક hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	મુક્ત(string);
}

સ્થિર શૂન્ય
send_names(uint32_t id, પૂર્ણાંક ગણતરી, અચલ Stat *stats)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક i, r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, ગણતરી)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, ગણતરી);
	માટે (i = 0; i < ગણતરી; i++) {
		જો ((r = sshbuf_put_cstring(સંદેશ, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(સંદેશ, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
send_attrib(uint32_t id, અચલ Attrib *a)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = encode_attrib(સંદેશ, a)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
send_statvfs(uint32_t id, સંરચના statvfs *st)
{
	સંરચના sshbuf *સંદેશ;
	uint64_t flag;
	પૂર્ણાંક r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, flag)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
સ્થિર પૂર્ણાંક
compose_extension(સંરચના sshbuf *સંદેશ, અચલ અક્ષર *name, અચલ અક્ષર *ver)
{
	પૂર્ણાંક r;
	અચલ સંરચના sftp_handler *exthnd;

	જો ((exthnd = extended_handler_byname(name)) == ખાલી)
		fatal_f("internal error: no handler for %s", name);
	જો (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		પાછા 0;
	}
	જો ((r = sshbuf_put_cstring(સંદેશ, name)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	પાછા 0;
}

/* parse incoming */

સ્થિર શૂન્ય
process_init(શૂન્ય)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(સંદેશ, "posix-rename@openssh.com", "1");
	compose_extension(સંદેશ, "statvfs@openssh.com", "2");
	compose_extension(સંદેશ, "fstatvfs@openssh.com", "2");
	compose_extension(સંદેશ, "hardlink@openssh.com", "1");
	compose_extension(સંદેશ, "fsync@openssh.com", "1");
	compose_extension(સંદેશ, "lsetstat@openssh.com", "1");
	compose_extension(સંદેશ, "limits@openssh.com", "1");
	compose_extension(સંદેશ, "expand-path@openssh.com", "1");
	compose_extension(સંદેશ, "copy-data", "1");
	compose_extension(સંદેશ, "home-directory", "1");
	compose_extension(સંદેશ, "users-groups-by-id@openssh.com", "1");

	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	અક્ષર *name;
	પૂર્ણાંક r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	જો (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} નહીંતર {
		fd = open(name, flags, mode);
		જો (fd == -1) {
			status = errno_to_portable(errno);
		} નહીંતર {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ખાલી);
			જો (handle < 0) {
				close(fd);
			} નહીંતર {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	જો (status != SSH2_FX_OK)
		send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_close(uint32_t id)
{
	પૂર્ણાંક r, handle, ret, status = SSH2_FX_FAILURE;

	જો ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ખાલી);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

સ્થિર શૂન્ય
process_read(uint32_t id)
{
	સ્થિર u_char *buf;
	સ્થિર size_t buflen;
	uint32_t len;
	પૂર્ણાંક r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	જો ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	જો ((fd = handle_to_fd(handle)) == -1)
		જાઓ out;
	જો (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	જો (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		જો ((buf = realloc(buf, len)) == ખાલી)
			fatal_f("realloc failed");
		buflen = len;
	}
	જો (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		જાઓ out;
	}
	જો (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} નહીંતર જો ((ret = પઠ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		જાઓ out;
	} નહીંતર જો (ret == 0) {
		status = SSH2_FX_EOF;
		જાઓ out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	જો (status != SSH2_FX_OK)
		send_status(id, status);
}

સ્થિર શૂન્ય
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	પૂર્ણાંક r, handle, fd, ret, status;
	u_char *data;

	જો ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	જો (fd < 0)
		status = SSH2_FX_FAILURE;
	નહીંતર {
		જો (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} નહીંતર {
/* XXX ATOMICIO ? */
			ret = લિખ(fd, data, len);
			જો (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} નહીંતર જો ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} નહીંતર {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	મુક્ત(data);
}

સ્થિર શૂન્ય
process_do_stat(uint32_t id, પૂર્ણાંક do_lstat)
{
	Attrib a;
	સંરચના stat st;
	અક્ષર *name;
	પૂર્ણાંક r, status = SSH2_FX_FAILURE;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	જો (r == -1) {
		status = errno_to_portable(errno);
	} નહીંતર {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	જો (status != SSH2_FX_OK)
		send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

સ્થિર શૂન્ય
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

સ્થિર શૂન્ય
process_fstat(uint32_t id)
{
	Attrib a;
	સંરચના stat st;
	પૂર્ણાંક fd, r, handle, status = SSH2_FX_FAILURE;

	જો ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	જો (fd >= 0) {
		r = fstat(fd, &st);
		જો (r == -1) {
			status = errno_to_portable(errno);
		} નહીંતર {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	જો (status != SSH2_FX_OK)
		send_status(id, status);
}

સ્થિર સંરચના timeval *
attrib_to_tv(અચલ Attrib *a)
{
	સ્થિર સંરચના timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	પાછા tv;
}

સ્થિર સંરચના timespec *
attrib_to_ts(અચલ Attrib *a)
{
	સ્થિર સંરચના timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	પાછા ts;
}

સ્થિર શૂન્ય
process_setstat(uint32_t id)
{
	Attrib a;
	અક્ષર *name;
	પૂર્ણાંક r, status = SSH2_FX_OK;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	જો (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		અક્ષર buf[64];
		time_t t = a.mtime;

		strftime(buf, કદ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_fsetstat(uint32_t id)
{
	Attrib a;
	પૂર્ણાંક handle, fd, r;
	પૂર્ણાંક status = SSH2_FX_OK;

	જો ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	જો (fd < 0)
		status = SSH2_FX_FAILURE;
	નહીંતર {
		અક્ષર *name = handle_to_name(handle);

		જો (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			જો (r == -1)
				status = errno_to_portable(errno);
		}
		જો (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#નહીંતર
			r = chmod(name, a.perm & 07777);
#endif
			જો (r == -1)
				status = errno_to_portable(errno);
		}
		જો (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			અક્ષર buf[64];
			time_t t = a.mtime;

			strftime(buf, કદ(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#નહીંતર
			r = utimes(name, attrib_to_tv(&a));
#endif
			જો (r == -1)
				status = errno_to_portable(errno);
		}
		જો (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#નહીંતર
			r = chown(name, a.uid, a.gid);
#endif
			જો (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

સ્થિર શૂન્ય
process_opendir(uint32_t id)
{
	DIR *dirp = ખાલી;
	અક્ષર *path;
	પૂર્ણાંક r, handle, status = SSH2_FX_FAILURE;

	જો ((r = sshbuf_get_cstring(iqueue, &path, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	જો (dirp == ખાલી) {
		status = errno_to_portable(errno);
	} નહીંતર {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		જો (handle < 0) {
			closedir(dirp);
		} નહીંતર {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	જો (status != SSH2_FX_OK)
		send_status(id, status);
	મુક્ત(path);
}

સ્થિર શૂન્ય
process_readdir(uint32_t id)
{
	DIR *dirp;
	સંરચના dirent *dp;
	અક્ષર *path;
	પૂર્ણાંક r, handle;

	જો ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	જો (dirp == ખાલી || path == ખાલી) {
		send_status(id, SSH2_FX_FAILURE);
	} નહીંતર {
		સંરચના stat st;
		અક્ષર *pathname;
		Stat *stats;
		પૂર્ણાંક nstats = 10, ગણતરી = 0, i;

		stats = xcalloc(nstats, કદ(Stat));
		જ્યારે ((dp = readdir(dirp)) != ખાલી) {
			જો (ગણતરી >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, કદ(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			મુક્ત(pathname);
			જો (r == -1)
				ચાલુ;
			stat_to_attrib(&st, &(stats[ગણતરી].attrib));
			stats[ગણતરી].name = xstrdup(dp->d_name);
			stats[ગણતરી].long_name = ls_file(dp->d_name, &st,
			    0, 0, ખાલી, ખાલી);
			ગણતરી++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			જો (ગણતરી == 100)
				તોડો;
		}
		જો (ગણતરી > 0) {
			send_names(id, ગણતરી, stats);
			માટે (i = 0; i < ગણતરી; i++) {
				મુક્ત(stats[i].name);
				મુક્ત(stats[i].long_name);
			}
		} નહીંતર {
			send_status(id, SSH2_FX_EOF);
		}
		મુક્ત(stats);
	}
}

સ્થિર શૂન્ય
process_remove(uint32_t id)
{
	અક્ષર *name;
	પૂર્ણાંક r, status = SSH2_FX_FAILURE;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_mkdir(uint32_t id)
{
	Attrib a;
	અક્ષર *name;
	પૂર્ણાંક r, mode, status = SSH2_FX_FAILURE;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_rmdir(uint32_t id)
{
	અક્ષર *name;
	પૂર્ણાંક r, status;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_realpath(uint32_t id)
{
	અક્ષર resolvedname[PATH_MAX];
	અક્ષર *path;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_cstring(iqueue, &path, ખાલી)) != 0)
		fatal_fr(r, "parse");

	જો (path[0] == '\0') {
		મુક્ત(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	જો (sftp_realpath(path, resolvedname) == ખાલી) {
		send_status(id, errno_to_portable(errno));
	} નહીંતર {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	મુક્ત(path);
}

સ્થિર શૂન્ય
process_rename(uint32_t id)
{
	અક્ષર *oldpath, *newpath;
	પૂર્ણાંક r, status;
	સંરચના stat sb;

	જો ((r = sshbuf_get_cstring(iqueue, &oldpath, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	જો (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	નહીંતર જો (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		જો (link(oldpath, newpath) == -1) {
			જો (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				સંરચના stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				જો (stat(newpath, &st) == -1) {
					જો (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					નહીંતર
						status = SSH2_FX_OK;
				}
			} નહીંતર {
				status = errno_to_portable(errno);
			}
		} નહીંતર જો (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} નહીંતર
			status = SSH2_FX_OK;
	} નહીંતર જો (stat(newpath, &sb) == -1) {
		જો (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		નહીંતર
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	મુક્ત(oldpath);
	મુક્ત(newpath);
}

સ્થિર શૂન્ય
process_readlink(uint32_t id)
{
	પૂર્ણાંક r, len;
	અક્ષર buf[PATH_MAX];
	અક્ષર *path;

	જો ((r = sshbuf_get_cstring(iqueue, &path, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	જો ((len = readlink(path, buf, કદ(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	નહીંતર {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	મુક્ત(path);
}

સ્થિર શૂન્ય
process_symlink(uint32_t id)
{
	અક્ષર *oldpath, *newpath;
	પૂર્ણાંક r, status;

	જો ((r = sshbuf_get_cstring(iqueue, &oldpath, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(oldpath);
	મુક્ત(newpath);
}

સ્થિર શૂન્ય
process_extended_posix_rename(uint32_t id)
{
	અક્ષર *oldpath, *newpath;
	પૂર્ણાંક r, status;

	જો ((r = sshbuf_get_cstring(iqueue, &oldpath, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(oldpath);
	મુક્ત(newpath);
}

સ્થિર શૂન્ય
process_extended_statvfs(uint32_t id)
{
	અક્ષર *path;
	સંરચના statvfs st;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_cstring(iqueue, &path, ખાલી)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	જો (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	નહીંતર
		send_statvfs(id, &st);
	મુક્ત(path);
}

સ્થિર શૂન્ય
process_extended_fstatvfs(uint32_t id)
{
	પૂર્ણાંક r, handle, fd;
	સંરચના statvfs st;

	જો ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	જો ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		પાછા;
	}
	જો (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	નહીંતર
		send_statvfs(id, &st);
}

સ્થિર શૂન્ય
process_extended_hardlink(uint32_t id)
{
	અક્ષર *oldpath, *newpath;
	પૂર્ણાંક r, status;

	જો ((r = sshbuf_get_cstring(iqueue, &oldpath, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	મુક્ત(oldpath);
	મુક્ત(newpath);
}

સ્થિર શૂન્ય
process_extended_fsync(uint32_t id)
{
	પૂર્ણાંક handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	જો ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	જો ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	નહીંતર જો (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

સ્થિર શૂન્ય
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	અક્ષર *name;
	પૂર્ણાંક r, status = SSH2_FX_OK;

	જો ((r = sshbuf_get_cstring(iqueue, &name, ખાલી)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	જો (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		જાઓ out;
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		અક્ષર buf[64];
		time_t t = a.mtime;

		strftime(buf, કદ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
	જો (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		જો (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	મુક્ત(name);
}

સ્થિર શૂન્ય
process_extended_limits(uint32_t id)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;
	uint64_t nfiles = 0;
#જો defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	સંરચના rlimit rlim;
#endif

	debug("request %u: limits", id);

#જો defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	જો (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(સંદેશ, SFTP_MAX_સંદેશ_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(સંદેશ, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(સંદેશ, SFTP_MAX_સંદેશ_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(સંદેશ, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
process_extended_expand(uint32_t id)
{
	અક્ષર cwd[PATH_MAX], resolvedname[PATH_MAX];
	અક્ષર *path, *npath;
	પૂર્ણાંક r;
	Stat s;

	જો ((r = sshbuf_get_cstring(iqueue, &path, ખાલી)) != 0)
		fatal_fr(r, "parse");
	જો (getcwd(cwd, કદ(cwd)) == ખાલી) {
		send_status(id, errno_to_portable(errno));
		જાઓ out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	જો (path[0] == '\0') {
		/* empty path */
		મુક્ત(path);
		path = xstrdup(".");
	} નહીંતર જો (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		જો (strcmp(path, "~") == 0) {
			મુક્ત(path);
			path = xstrdup(cwd);
		} નહીંતર જો (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			મુક્ત(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			મુક્ત(npath);
		} નહીંતર {
			/* ~user expansions */
			જો (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				જાઓ out;
			}
			મુક્ત(path);
			path = npath;
		}
	} નહીંતર જો (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		મુક્ત(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	જો (sftp_realpath(path, resolvedname) == ખાલી) {
		send_status(id, errno_to_portable(errno));
		જાઓ out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	મુક્ત(path);
}

સ્થિર શૂન્ય
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	પૂર્ણાંક read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	પૂર્ણાંક r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	સંરચના stat st_read, st_write;

	જો ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	જો (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} નહીંતર
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	જો (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		જાઓ out;
	}
	જો (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		જાઓ out;
	}
	જો (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		જાઓ out;
	}
	જો (read_handle == write_handle ||
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
		જાઓ out;
	}

	જો (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		જાઓ out;
	}

	જો ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		જાઓ out;
	}

	/* Process the request in chunks. */
	જ્યારે (read_len > 0 || copy_until_eof) {
		len = MINIMUM(કદ(buf), read_len);
		read_len -= len;

		ret = atomicio(પઠ, read_fd, buf, len);
		જો (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			તોડો;
		} નહીંતર જો (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			તોડો;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		જો (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			તોડો;
		}
		handle_update_write(write_handle, len);
	}

	જો (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

સ્થિર શૂન્ય
process_extended_home_directory(uint32_t id)
{
	અક્ષર *username;
	સંરચના passwd *user_pw;
	પૂર્ણાંક r;
	Stat s;

	જો ((r = sshbuf_get_cstring(iqueue, &username, ખાલી)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	જો (username[0] == '\0') {
		user_pw = pw;
	} નહીંતર જો ((user_pw = getpwnam(username)) == ખાલી) {
		send_status(id, SSH2_FX_FAILURE);
		જાઓ out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	મુક્ત(username);
}

સ્થિર શૂન્ય
process_extended_get_users_groups_by_id(uint32_t id)
{
	સંરચના passwd *user_pw;
	સંરચના group *gr;
	સંરચના sshbuf *uids, *gids, *usernames, *groupnames, *સંદેશ;
	પૂર્ણાંક r;
	u_int n, nusers = 0, ngroups = 0;
	અચલ અક્ષર *name;

	જો ((usernames = sshbuf_new()) == ખાલી ||
	    (groupnames = sshbuf_new()) == ખાલી ||
	    (સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	જ્યારે (sshbuf_len(uids) != 0) {
		જો ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ખાલી ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		જો ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	જ્યારે (sshbuf_len(gids) != 0) {
		જો ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ખાલી ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		જો ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(સંદેશ);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
process_extended(uint32_t id)
{
	અક્ષર *request;
	પૂર્ણાંક r;
	અચલ સંરચના sftp_handler *exthand;

	જો ((r = sshbuf_get_cstring(iqueue, &request, ખાલી)) != 0)
		fatal_fr(r, "parse");
	જો ((exthand = extended_handler_byname(request)) == ખાલી) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} નહીંતર {
		જો (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		નહીંતર
			exthand->handler(id);
	}
	મુક્ત(request);
}

/* stolen from ssh-agent */

સ્થિર શૂન્ય
process(શૂન્ય)
{
	u_int સંદેશ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	અચલ u_char *cp;
	પૂર્ણાંક i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	જો (buf_len < 5)
		પાછા;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	સંદેશ_len = get_u32(cp);
	જો (સંદેશ_len > SFTP_MAX_સંદેશ_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	જો (buf_len < સંદેશ_len + 4)
		પાછા;
	જો ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	જો ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	પસંદગી (type) {
	સ્થિતિ SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		તોડો;
	સ્થિતિ SSH2_FXP_EXTENDED:
		જો (!init_done)
			fatal("Received extended request before init");
		જો ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		તોડો;
	મૂળભૂત:
		જો (!init_done)
			fatal("Received %u request before init", type);
		જો ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		માટે (i = 0; handlers[i].handler != ખાલી; i++) {
			જો (type == handlers[i].type) {
				જો (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} નહીંતર {
					handlers[i].handler(id);
				}
				તોડો;
			}
		}
		જો (handlers[i].handler == ખાલી)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	જો (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	જો (સંદેશ_len < consumed) {
		error("msg_len %u < consumed %u", સંદેશ_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	જો (સંદેશ_len > consumed &&
	    (r = sshbuf_consume(iqueue, સંદેશ_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
શૂન્ય
sftp_server_cleanup_exit(પૂર્ણાંક i)
{
	જો (pw != ખાલી && client_addr != ખાલી) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

સ્થિર શૂન્ય
sftp_server_usage(શૂન્ય)
{
	બાહ્ય અક્ષર *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

પૂર્ણાંક
sftp_server_main(પૂર્ણાંક argc, અક્ષર **argv, સંરચના passwd *user_pw)
{
	પૂર્ણાંક i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	અક્ષર *cp, *homedir = ખાલી, uidstr[32], buf[4*4096];
	long mask;

	બાહ્ય અક્ષર *optarg;
	બાહ્ય અક્ષર *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	જ્યારે (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'Q':
			જો (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			માટે (i = 0; handlers[i].handler != ખાલી; i++)
				printf("%s\n", handlers[i].name);
			માટે (i = 0; extended_handlers[i].handler != ખાલી; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			તોડો;
		સ્થિતિ 'R':
			readonly = 1;
			તોડો;
		સ્થિતિ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			તોડો;
		સ્થિતિ 'e':
			log_stderr = 1;
			તોડો;
		સ્થિતિ 'l':
			log_level = log_level_સંખ્યા(optarg);
			જો (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'f':
			log_facility = log_facility_સંખ્યા(optarg);
			જો (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, કદ(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (અક્ષર *)ખાલી);
			મુક્ત(cp);
			તોડો;
		સ્થિતિ 'p':
			જો (request_allowlist != ખાલી)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'P':
			જો (request_denylist != ખાલી)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			જો (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(શૂન્ય)umask((mode_t)mask);
			તોડો;
		સ્થિતિ 'h':
		મૂળભૂત:
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

	જો ((cp = getenv("SSH_CONNECTION")) != ખાલી) {
		client_addr = xstrdup(cp);
		જો ((cp = strchr(client_addr, ' ')) == ખાલી) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} નહીંતર
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_દ્વિઅંકી);
	setmode(out, O_દ્વિઅંકી);
#endif

	જો ((iqueue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((oqueue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જો (homedir != ખાલી) {
		જો (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	માટે (;;) {
		સંરચના pollfd pfd[2];

		memset(pfd, 0, કદ pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		જો ((r = sshbuf_check_reserve(iqueue, કદ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_સંદેશ_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		નહીંતર જો (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		જો (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		જો (poll(pfd, 2, -1) == -1) {
			જો (errno == EINTR)
				ચાલુ;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		જો (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = પઠ(in, buf, કદ buf);
			જો (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} નહીંતર જો (len == -1) {
				જો (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} નહીંતર જો ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		જો (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = લિખ(out, sshbuf_ptr(oqueue), olen);
			જો (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} નહીંતર જો (len == -1) {
				sftp_server_cleanup_exit(1);
				જો (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} નહીંતર જો ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_સંદેશ_LENGTH);
		જો (r == 0)
			process();
		નહીંતર જો (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
