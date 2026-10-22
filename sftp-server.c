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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/resource.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/statvfs.h>

#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "uidswap.h"

#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "sftp-common.h"

எழுத்து *sftp_realpath(மாறிலி எழுத்து *, எழுத்து *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_செய்தி_LENGTH - 1024)

/* Our verbosity */
நிலையான LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
நிலையான கட்டமைப்பு passwd *pw = வெற்று;
நிலையான எழுத்து *client_addr = வெற்று;

/* input and output queue */
கட்டமைப்பு sshbuf *iqueue;
கட்டமைப்பு sshbuf *oqueue;

/* Version of client */
நிலையான u_int version;

/* SSH2_FXP_INIT received */
நிலையான முழு init_done;

/* Disable writes */
நிலையான முழு readonly;

/* Requests that are allowed/denied */
நிலையான எழுத்து *request_allowlist, *request_denylist;

/* portable attributes, etc. */
வகைவரை கட்டமைப்பு Stat Stat;

கட்டமைப்பு Stat {
	எழுத்து *name;
	எழுத்து *long_name;
	Attrib attrib;
};

/* Packet handlers */
நிலையான வெறுமை process_open(uint32_t id);
நிலையான வெறுமை process_close(uint32_t id);
நிலையான வெறுமை process_read(uint32_t id);
நிலையான வெறுமை process_write(uint32_t id);
நிலையான வெறுமை process_stat(uint32_t id);
நிலையான வெறுமை process_lstat(uint32_t id);
நிலையான வெறுமை process_fstat(uint32_t id);
நிலையான வெறுமை process_setstat(uint32_t id);
நிலையான வெறுமை process_fsetstat(uint32_t id);
நிலையான வெறுமை process_opendir(uint32_t id);
நிலையான வெறுமை process_readdir(uint32_t id);
நிலையான வெறுமை process_remove(uint32_t id);
நிலையான வெறுமை process_mkdir(uint32_t id);
நிலையான வெறுமை process_rmdir(uint32_t id);
நிலையான வெறுமை process_realpath(uint32_t id);
நிலையான வெறுமை process_rename(uint32_t id);
நிலையான வெறுமை process_readlink(uint32_t id);
நிலையான வெறுமை process_symlink(uint32_t id);
நிலையான வெறுமை process_extended_posix_rename(uint32_t id);
நிலையான வெறுமை process_extended_statvfs(uint32_t id);
நிலையான வெறுமை process_extended_fstatvfs(uint32_t id);
நிலையான வெறுமை process_extended_hardlink(uint32_t id);
நிலையான வெறுமை process_extended_fsync(uint32_t id);
நிலையான வெறுமை process_extended_lsetstat(uint32_t id);
நிலையான வெறுமை process_extended_limits(uint32_t id);
நிலையான வெறுமை process_extended_expand(uint32_t id);
நிலையான வெறுமை process_extended_copy_data(uint32_t id);
நிலையான வெறுமை process_extended_home_directory(uint32_t id);
நிலையான வெறுமை process_extended_get_users_groups_by_id(uint32_t id);
நிலையான வெறுமை process_extended(uint32_t id);

கட்டமைப்பு sftp_handler {
	மாறிலி எழுத்து *name;	/* user-visible name for fine-grained perms */
	மாறிலி எழுத்து *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	வெறுமை (*handler)(uint32_t);
	முழு does_write;		/* if nonzero, banned for readonly mode */
};

நிலையான மாறிலி கட்டமைப்பு sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", வெற்று, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", வெற்று, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", வெற்று, SSH2_FXP_READ, process_read, 0 },
	{ "write", வெற்று, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", வெற்று, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", வெற்று, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", வெற்று, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", வெற்று, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", வெற்று, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", வெற்று, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", வெற்று, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", வெற்று, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", வெற்று, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", வெற்று, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", வெற்று, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", வெற்று, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", வெற்று, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", வெற்று, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ வெற்று, வெற்று, 0, வெற்று, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
நிலையான மாறிலி கட்டமைப்பு sftp_handler extended_handlers[] = {
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
	{ வெற்று, வெற்று, 0, வெற்று, 0 }
};

நிலையான மாறிலி கட்டமைப்பு sftp_handler *
extended_handler_byname(மாறிலி எழுத்து *name)
{
	முழு i;

	க்கு (i = 0; extended_handlers[i].handler != வெற்று; i++) {
		எனில் (strcmp(name, extended_handlers[i].ext_name) == 0)
			திரும்பு &extended_handlers[i];
	}
	திரும்பு வெற்று;
}

நிலையான முழு
request_permitted(மாறிலி கட்டமைப்பு sftp_handler *h)
{
	எழுத்து *result;

	எனில் (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		திரும்பு 0;
	}
	எனில் (request_denylist != வெற்று &&
	    ((result = match_list(h->name, request_denylist, வெற்று))) != வெற்று) {
		விடுவி(result);
		verbose("Refusing denylisted %s request", h->name);
		திரும்பு 0;
	}
	எனில் (request_allowlist != வெற்று &&
	    ((result = match_list(h->name, request_allowlist, வெற்று))) != வெற்று) {
		விடுவி(result);
		debug2("Permitting allowlisted %s request", h->name);
		திரும்பு 1;
	}
	எனில் (request_allowlist != வெற்று) {
		verbose("Refusing non-allowlisted %s request", h->name);
		திரும்பு 0;
	}
	திரும்பு 1;
}

நிலையான முழு
errno_to_portable(முழு unixerrno)
{
	முழு ret = 0;

	தேர்வு (unixerrno) {
	நிலை 0:
		ret = SSH2_FX_OK;
		நிறுத்து;
	நிலை ENOENT:
	நிலை ENOTDIR:
	நிலை EBADF:
	நிலை ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		நிறுத்து;
	நிலை EPERM:
	நிலை EACCES:
	நிலை EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		நிறுத்து;
	நிலை ENAMETOOLONG:
	நிலை EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		நிறுத்து;
	நிலை ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		நிறுத்து;
	இயல்பு:
		ret = SSH2_FX_FAILURE;
		நிறுத்து;
	}
	திரும்பு ret;
}

நிலையான முழு
flags_from_portable(முழு pflags)
{
	முழு flags = 0;

	எனில் ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} இல்லையெனில் எனில் (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} இல்லையெனில் எனில் (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	எனில் (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	எனில் (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	எனில் (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	எனில் (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	திரும்பு flags;
}

நிலையான மாறிலி எழுத்து *
string_from_portable(முழு pflags)
{
	நிலையான எழுத்து ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		எனில் (*ret != '\0')			\
			strlcat(ret, ",", அளவு(ret));	\
		strlcat(ret, str, அளவு(ret));		\
	}

	எனில் (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	எனில் (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	எனில் (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	எனில் (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	எனில் (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	எனில் (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	திரும்பு ret;
}

/* handle handles */

வகைவரை கட்டமைப்பு Handle Handle;
கட்டமைப்பு Handle {
	முழு use;
	DIR *dirp;
	முழு fd;
	முழு flags;
	எழுத்து *name;
	uint64_t bytes_read, bytes_write;
	முழு next_unused;
};

எண்ணிக்கை {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

நிலையான Handle *handles = வெற்று;
நிலையான u_int இலக்கம்_handles = 0;
நிலையான முழு first_unused_handle = -1;

நிலையான வெறுமை handle_unused(முழு i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

நிலையான முழு
handle_new(முழு use, மாறிலி எழுத்து *name, முழு fd, முழு flags, DIR *dirp)
{
	முழு i;

	எனில் (first_unused_handle == -1) {
		எனில் (இலக்கம்_handles + 1 <= இலக்கம்_handles)
			திரும்பு -1;
		இலக்கம்_handles++;
		handles = xreallocarray(handles, இலக்கம்_handles, அளவு(Handle));
		handle_unused(இலக்கம்_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	திரும்பு i;
}

நிலையான முழு
handle_is_ok(முழு i, முழு type)
{
	திரும்பு i >= 0 && (u_int)i < இலக்கம்_handles && handles[i].use == type;
}

நிலையான முழு
handle_to_string(முழு handle, u_char **stringp, முழு *hlenp)
{
	எனில் (stringp == வெற்று || hlenp == வெற்று)
		திரும்பு -1;
	*stringp = xmalloc(அளவு(int32_t));
	put_u32(*stringp, handle);
	*hlenp = அளவு(int32_t);
	திரும்பு 0;
}

நிலையான முழு
handle_from_string(மாறிலி u_char *handle, u_int hlen)
{
	முழு val;

	எனில் (hlen != அளவு(int32_t))
		திரும்பு -1;
	val = get_u32(handle);
	எனில் (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		திரும்பு val;
	திரும்பு -1;
}

நிலையான எழுத்து *
handle_to_name(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		திரும்பு handles[handle].name;
	திரும்பு வெற்று;
}

நிலையான DIR *
handle_to_dir(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_DIR))
		திரும்பு handles[handle].dirp;
	திரும்பு வெற்று;
}

நிலையான முழு
handle_to_fd(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE))
		திரும்பு handles[handle].fd;
	திரும்பு -1;
}

நிலையான முழு
handle_to_flags(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE))
		திரும்பு handles[handle].flags;
	திரும்பு 0;
}

நிலையான வெறுமை
handle_update_read(முழு handle, ssize_t bytes)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

நிலையான வெறுமை
handle_update_write(முழு handle, ssize_t bytes)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

நிலையான uint64_t
handle_bytes_read(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE))
		திரும்பு (handles[handle].bytes_read);
	திரும்பு 0;
}

நிலையான uint64_t
handle_bytes_write(முழு handle)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE))
		திரும்பு (handles[handle].bytes_write);
	திரும்பு 0;
}

நிலையான முழு
handle_close(முழு handle)
{
	முழு ret = -1;

	எனில் (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		விடுவி(handles[handle].name);
		handle_unused(handle);
	} இல்லையெனில் எனில் (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		விடுவி(handles[handle].name);
		handle_unused(handle);
	} இல்லையெனில் {
		errno = ENOENT;
	}
	திரும்பு ret;
}

நிலையான வெறுமை
handle_log_close(முழு handle, எழுத்து *emsg)
{
	எனில் (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == வெற்று ? "" : emsg, emsg == வெற்று ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} இல்லையெனில் {
		logit("%s%sclosedir \"%s\"",
		    emsg == வெற்று ? "" : emsg, emsg == வெற்று ? "" : " ",
		    handle_to_name(handle));
	}
}

நிலையான வெறுமை
handle_log_exit(வெறுமை)
{
	u_int i;

	க்கு (i = 0; i < இலக்கம்_handles; i++)
		எனில் (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

நிலையான முழு
get_handle(கட்டமைப்பு sshbuf *queue, முழு *hp)
{
	u_char *handle;
	முழு r;
	size_t hlen;

	*hp = -1;
	எனில் ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		திரும்பு r;
	எனில் (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	விடுவி(handle);
	திரும்பு 0;
}

/* send replies */

நிலையான வெறுமை
send_செய்தி(கட்டமைப்பு sshbuf *m)
{
	முழு r;

	எனில் ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

நிலையான மாறிலி எழுத்து *
status_to_message(uint32_t status)
{
	நிலையான மாறிலி எழுத்து * மாறிலி status_messages[] = {
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
	திரும்பு (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

நிலையான வெறுமை
send_status_errmsg(uint32_t id, uint32_t status, மாறிலி எழுத்து *errmsg)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	debug3("request %u: sent status %u", id, status);
	எனில் (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, status)) != 0)
		fatal_fr(r, "compose");
	எனில் (version >= 3) {
		எனில் ((r = sshbuf_put_cstring(செய்தி, errmsg == வெற்று ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, வெற்று);
}

நிலையான வெறுமை
send_data_or_handle(எழுத்து type, uint32_t id, மாறிலி u_char *data, முழு dlen)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, type)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
send_data(uint32_t id, மாறிலி u_char *data, முழு dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

நிலையான வெறுமை
send_handle(uint32_t id, முழு handle)
{
	u_char *string;
	முழு hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	விடுவி(string);
}

நிலையான வெறுமை
send_names(uint32_t id, முழு மொத்தம், மாறிலி Stat *stats)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு i, r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, மொத்தம்)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, மொத்தம்);
	க்கு (i = 0; i < மொத்தம்; i++) {
		எனில் ((r = sshbuf_put_cstring(செய்தி, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(செய்தி, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
send_attrib(uint32_t id, மாறிலி Attrib *a)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = encode_attrib(செய்தி, a)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
send_statvfs(uint32_t id, கட்டமைப்பு statvfs *st)
{
	கட்டமைப்பு sshbuf *செய்தி;
	uint64_t flag;
	முழு r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, flag)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
நிலையான முழு
compose_extension(கட்டமைப்பு sshbuf *செய்தி, மாறிலி எழுத்து *name, மாறிலி எழுத்து *ver)
{
	முழு r;
	மாறிலி கட்டமைப்பு sftp_handler *exthnd;

	எனில் ((exthnd = extended_handler_byname(name)) == வெற்று)
		fatal_f("internal error: no handler for %s", name);
	எனில் (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		திரும்பு 0;
	}
	எனில் ((r = sshbuf_put_cstring(செய்தி, name)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	திரும்பு 0;
}

/* parse incoming */

நிலையான வெறுமை
process_init(வெறுமை)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(செய்தி, "posix-rename@openssh.com", "1");
	compose_extension(செய்தி, "statvfs@openssh.com", "2");
	compose_extension(செய்தி, "fstatvfs@openssh.com", "2");
	compose_extension(செய்தி, "hardlink@openssh.com", "1");
	compose_extension(செய்தி, "fsync@openssh.com", "1");
	compose_extension(செய்தி, "lsetstat@openssh.com", "1");
	compose_extension(செய்தி, "limits@openssh.com", "1");
	compose_extension(செய்தி, "expand-path@openssh.com", "1");
	compose_extension(செய்தி, "copy-data", "1");
	compose_extension(செய்தி, "home-directory", "1");
	compose_extension(செய்தி, "users-groups-by-id@openssh.com", "1");

	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	எழுத்து *name;
	முழு r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	எனில் (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} இல்லையெனில் {
		fd = open(name, flags, mode);
		எனில் (fd == -1) {
			status = errno_to_portable(errno);
		} இல்லையெனில் {
			handle = handle_new(HANDLE_FILE, name, fd, flags, வெற்று);
			எனில் (handle < 0) {
				close(fd);
			} இல்லையெனில் {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	எனில் (status != SSH2_FX_OK)
		send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_close(uint32_t id)
{
	முழு r, handle, ret, status = SSH2_FX_FAILURE;

	எனில் ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, வெற்று);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

நிலையான வெறுமை
process_read(uint32_t id)
{
	நிலையான u_char *buf;
	நிலையான size_t buflen;
	uint32_t len;
	முழு r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	எனில் ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	எனில் ((fd = handle_to_fd(handle)) == -1)
		செல் out;
	எனில் (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	எனில் (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		எனில் ((buf = realloc(buf, len)) == வெற்று)
			fatal_f("realloc failed");
		buflen = len;
	}
	எனில் (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		செல் out;
	}
	எனில் (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} இல்லையெனில் எனில் ((ret = பட(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		செல் out;
	} இல்லையெனில் எனில் (ret == 0) {
		status = SSH2_FX_EOF;
		செல் out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	எனில் (status != SSH2_FX_OK)
		send_status(id, status);
}

நிலையான வெறுமை
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	முழு r, handle, fd, ret, status;
	u_char *data;

	எனில் ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	எனில் (fd < 0)
		status = SSH2_FX_FAILURE;
	இல்லையெனில் {
		எனில் (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} இல்லையெனில் {
/* XXX ATOMICIO ? */
			ret = லிக(fd, data, len);
			எனில் (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} இல்லையெனில் எனில் ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} இல்லையெனில் {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	விடுவி(data);
}

நிலையான வெறுமை
process_do_stat(uint32_t id, முழு do_lstat)
{
	Attrib a;
	கட்டமைப்பு stat st;
	எழுத்து *name;
	முழு r, status = SSH2_FX_FAILURE;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	எனில் (r == -1) {
		status = errno_to_portable(errno);
	} இல்லையெனில் {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	எனில் (status != SSH2_FX_OK)
		send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

நிலையான வெறுமை
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

நிலையான வெறுமை
process_fstat(uint32_t id)
{
	Attrib a;
	கட்டமைப்பு stat st;
	முழு fd, r, handle, status = SSH2_FX_FAILURE;

	எனில் ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	எனில் (fd >= 0) {
		r = fstat(fd, &st);
		எனில் (r == -1) {
			status = errno_to_portable(errno);
		} இல்லையெனில் {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	எனில் (status != SSH2_FX_OK)
		send_status(id, status);
}

நிலையான கட்டமைப்பு timeval *
attrib_to_tv(மாறிலி Attrib *a)
{
	நிலையான கட்டமைப்பு timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	திரும்பு tv;
}

நிலையான கட்டமைப்பு timespec *
attrib_to_ts(மாறிலி Attrib *a)
{
	நிலையான கட்டமைப்பு timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	திரும்பு ts;
}

நிலையான வெறுமை
process_setstat(uint32_t id)
{
	Attrib a;
	எழுத்து *name;
	முழு r, status = SSH2_FX_OK;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	எனில் (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		எழுத்து buf[64];
		time_t t = a.mtime;

		strftime(buf, அளவு(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_fsetstat(uint32_t id)
{
	Attrib a;
	முழு handle, fd, r;
	முழு status = SSH2_FX_OK;

	எனில் ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	எனில் (fd < 0)
		status = SSH2_FX_FAILURE;
	இல்லையெனில் {
		எழுத்து *name = handle_to_name(handle);

		எனில் (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			எனில் (r == -1)
				status = errno_to_portable(errno);
		}
		எனில் (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#இல்லையெனில்
			r = chmod(name, a.perm & 07777);
#endif
			எனில் (r == -1)
				status = errno_to_portable(errno);
		}
		எனில் (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			எழுத்து buf[64];
			time_t t = a.mtime;

			strftime(buf, அளவு(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#இல்லையெனில்
			r = utimes(name, attrib_to_tv(&a));
#endif
			எனில் (r == -1)
				status = errno_to_portable(errno);
		}
		எனில் (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#இல்லையெனில்
			r = chown(name, a.uid, a.gid);
#endif
			எனில் (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

நிலையான வெறுமை
process_opendir(uint32_t id)
{
	DIR *dirp = வெற்று;
	எழுத்து *path;
	முழு r, handle, status = SSH2_FX_FAILURE;

	எனில் ((r = sshbuf_get_cstring(iqueue, &path, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	எனில் (dirp == வெற்று) {
		status = errno_to_portable(errno);
	} இல்லையெனில் {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		எனில் (handle < 0) {
			closedir(dirp);
		} இல்லையெனில் {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	எனில் (status != SSH2_FX_OK)
		send_status(id, status);
	விடுவி(path);
}

நிலையான வெறுமை
process_readdir(uint32_t id)
{
	DIR *dirp;
	கட்டமைப்பு dirent *dp;
	எழுத்து *path;
	முழு r, handle;

	எனில் ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	எனில் (dirp == வெற்று || path == வெற்று) {
		send_status(id, SSH2_FX_FAILURE);
	} இல்லையெனில் {
		கட்டமைப்பு stat st;
		எழுத்து *pathname;
		Stat *stats;
		முழு nstats = 10, மொத்தம் = 0, i;

		stats = xcalloc(nstats, அளவு(Stat));
		போது ((dp = readdir(dirp)) != வெற்று) {
			எனில் (மொத்தம் >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, அளவு(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			விடுவி(pathname);
			எனில் (r == -1)
				தொடர்;
			stat_to_attrib(&st, &(stats[மொத்தம்].attrib));
			stats[மொத்தம்].name = xstrdup(dp->d_name);
			stats[மொத்தம்].long_name = ls_file(dp->d_name, &st,
			    0, 0, வெற்று, வெற்று);
			மொத்தம்++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			எனில் (மொத்தம் == 100)
				நிறுத்து;
		}
		எனில் (மொத்தம் > 0) {
			send_names(id, மொத்தம், stats);
			க்கு (i = 0; i < மொத்தம்; i++) {
				விடுவி(stats[i].name);
				விடுவி(stats[i].long_name);
			}
		} இல்லையெனில் {
			send_status(id, SSH2_FX_EOF);
		}
		விடுவி(stats);
	}
}

நிலையான வெறுமை
process_remove(uint32_t id)
{
	எழுத்து *name;
	முழு r, status = SSH2_FX_FAILURE;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_mkdir(uint32_t id)
{
	Attrib a;
	எழுத்து *name;
	முழு r, mode, status = SSH2_FX_FAILURE;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_rmdir(uint32_t id)
{
	எழுத்து *name;
	முழு r, status;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_realpath(uint32_t id)
{
	எழுத்து resolvedname[PATH_MAX];
	எழுத்து *path;
	முழு r;

	எனில் ((r = sshbuf_get_cstring(iqueue, &path, வெற்று)) != 0)
		fatal_fr(r, "parse");

	எனில் (path[0] == '\0') {
		விடுவி(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	எனில் (sftp_realpath(path, resolvedname) == வெற்று) {
		send_status(id, errno_to_portable(errno));
	} இல்லையெனில் {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	விடுவி(path);
}

நிலையான வெறுமை
process_rename(uint32_t id)
{
	எழுத்து *oldpath, *newpath;
	முழு r, status;
	கட்டமைப்பு stat sb;

	எனில் ((r = sshbuf_get_cstring(iqueue, &oldpath, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	எனில் (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	இல்லையெனில் எனில் (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		எனில் (link(oldpath, newpath) == -1) {
			எனில் (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				கட்டமைப்பு stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				எனில் (stat(newpath, &st) == -1) {
					எனில் (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					இல்லையெனில்
						status = SSH2_FX_OK;
				}
			} இல்லையெனில் {
				status = errno_to_portable(errno);
			}
		} இல்லையெனில் எனில் (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} இல்லையெனில்
			status = SSH2_FX_OK;
	} இல்லையெனில் எனில் (stat(newpath, &sb) == -1) {
		எனில் (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		இல்லையெனில்
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	விடுவி(oldpath);
	விடுவி(newpath);
}

நிலையான வெறுமை
process_readlink(uint32_t id)
{
	முழு r, len;
	எழுத்து buf[PATH_MAX];
	எழுத்து *path;

	எனில் ((r = sshbuf_get_cstring(iqueue, &path, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	எனில் ((len = readlink(path, buf, அளவு(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	இல்லையெனில் {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	விடுவி(path);
}

நிலையான வெறுமை
process_symlink(uint32_t id)
{
	எழுத்து *oldpath, *newpath;
	முழு r, status;

	எனில் ((r = sshbuf_get_cstring(iqueue, &oldpath, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(oldpath);
	விடுவி(newpath);
}

நிலையான வெறுமை
process_extended_posix_rename(uint32_t id)
{
	எழுத்து *oldpath, *newpath;
	முழு r, status;

	எனில் ((r = sshbuf_get_cstring(iqueue, &oldpath, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(oldpath);
	விடுவி(newpath);
}

நிலையான வெறுமை
process_extended_statvfs(uint32_t id)
{
	எழுத்து *path;
	கட்டமைப்பு statvfs st;
	முழு r;

	எனில் ((r = sshbuf_get_cstring(iqueue, &path, வெற்று)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	எனில் (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	இல்லையெனில்
		send_statvfs(id, &st);
	விடுவி(path);
}

நிலையான வெறுமை
process_extended_fstatvfs(uint32_t id)
{
	முழு r, handle, fd;
	கட்டமைப்பு statvfs st;

	எனில் ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	எனில் ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		திரும்பு;
	}
	எனில் (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	இல்லையெனில்
		send_statvfs(id, &st);
}

நிலையான வெறுமை
process_extended_hardlink(uint32_t id)
{
	எழுத்து *oldpath, *newpath;
	முழு r, status;

	எனில் ((r = sshbuf_get_cstring(iqueue, &oldpath, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	விடுவி(oldpath);
	விடுவி(newpath);
}

நிலையான வெறுமை
process_extended_fsync(uint32_t id)
{
	முழு handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	எனில் ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	எனில் ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	இல்லையெனில் எனில் (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

நிலையான வெறுமை
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	எழுத்து *name;
	முழு r, status = SSH2_FX_OK;

	எனில் ((r = sshbuf_get_cstring(iqueue, &name, வெற்று)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	எனில் (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		செல் out;
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		எழுத்து buf[64];
		time_t t = a.mtime;

		strftime(buf, அளவு(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
	எனில் (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		எனில் (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	விடுவி(name);
}

நிலையான வெறுமை
process_extended_limits(uint32_t id)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;
	uint64_t nfiles = 0;
#எனில் defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	கட்டமைப்பு rlimit rlim;
#endif

	debug("request %u: limits", id);

#எனில் defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	எனில் (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(செய்தி, SFTP_MAX_செய்தி_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(செய்தி, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(செய்தி, SFTP_MAX_செய்தி_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(செய்தி, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
process_extended_expand(uint32_t id)
{
	எழுத்து cwd[PATH_MAX], resolvedname[PATH_MAX];
	எழுத்து *path, *npath;
	முழு r;
	Stat s;

	எனில் ((r = sshbuf_get_cstring(iqueue, &path, வெற்று)) != 0)
		fatal_fr(r, "parse");
	எனில் (getcwd(cwd, அளவு(cwd)) == வெற்று) {
		send_status(id, errno_to_portable(errno));
		செல் out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	எனில் (path[0] == '\0') {
		/* empty path */
		விடுவி(path);
		path = xstrdup(".");
	} இல்லையெனில் எனில் (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		எனில் (strcmp(path, "~") == 0) {
			விடுவி(path);
			path = xstrdup(cwd);
		} இல்லையெனில் எனில் (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			விடுவி(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			விடுவி(npath);
		} இல்லையெனில் {
			/* ~user expansions */
			எனில் (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				செல் out;
			}
			விடுவி(path);
			path = npath;
		}
	} இல்லையெனில் எனில் (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		விடுவி(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	எனில் (sftp_realpath(path, resolvedname) == வெற்று) {
		send_status(id, errno_to_portable(errno));
		செல் out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	விடுவி(path);
}

நிலையான வெறுமை
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	முழு read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	முழு r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	கட்டமைப்பு stat st_read, st_write;

	எனில் ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	எனில் (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} இல்லையெனில்
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	எனில் (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		செல் out;
	}
	எனில் (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		செல் out;
	}
	எனில் (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		செல் out;
	}
	எனில் (read_handle == write_handle ||
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
		செல் out;
	}

	எனில் (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		செல் out;
	}

	எனில் ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		செல் out;
	}

	/* Process the request in chunks. */
	போது (read_len > 0 || copy_until_eof) {
		len = MINIMUM(அளவு(buf), read_len);
		read_len -= len;

		ret = atomicio(பட, read_fd, buf, len);
		எனில் (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			நிறுத்து;
		} இல்லையெனில் எனில் (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			நிறுத்து;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		எனில் (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			நிறுத்து;
		}
		handle_update_write(write_handle, len);
	}

	எனில் (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

நிலையான வெறுமை
process_extended_home_directory(uint32_t id)
{
	எழுத்து *username;
	கட்டமைப்பு passwd *user_pw;
	முழு r;
	Stat s;

	எனில் ((r = sshbuf_get_cstring(iqueue, &username, வெற்று)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	எனில் (username[0] == '\0') {
		user_pw = pw;
	} இல்லையெனில் எனில் ((user_pw = getpwnam(username)) == வெற்று) {
		send_status(id, SSH2_FX_FAILURE);
		செல் out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	விடுவி(username);
}

நிலையான வெறுமை
process_extended_get_users_groups_by_id(uint32_t id)
{
	கட்டமைப்பு passwd *user_pw;
	கட்டமைப்பு group *gr;
	கட்டமைப்பு sshbuf *uids, *gids, *usernames, *groupnames, *செய்தி;
	முழு r;
	u_int n, nusers = 0, ngroups = 0;
	மாறிலி எழுத்து *name;

	எனில் ((usernames = sshbuf_new()) == வெற்று ||
	    (groupnames = sshbuf_new()) == வெற்று ||
	    (செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	போது (sshbuf_len(uids) != 0) {
		எனில் ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == வெற்று ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		எனில் ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	போது (sshbuf_len(gids) != 0) {
		எனில் ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == வெற்று ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		எனில் ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(செய்தி);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
process_extended(uint32_t id)
{
	எழுத்து *request;
	முழு r;
	மாறிலி கட்டமைப்பு sftp_handler *exthand;

	எனில் ((r = sshbuf_get_cstring(iqueue, &request, வெற்று)) != 0)
		fatal_fr(r, "parse");
	எனில் ((exthand = extended_handler_byname(request)) == வெற்று) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} இல்லையெனில் {
		எனில் (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		இல்லையெனில்
			exthand->handler(id);
	}
	விடுவி(request);
}

/* stolen from ssh-agent */

நிலையான வெறுமை
process(வெறுமை)
{
	u_int செய்தி_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	மாறிலி u_char *cp;
	முழு i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	எனில் (buf_len < 5)
		திரும்பு;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	செய்தி_len = get_u32(cp);
	எனில் (செய்தி_len > SFTP_MAX_செய்தி_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	எனில் (buf_len < செய்தி_len + 4)
		திரும்பு;
	எனில் ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	எனில் ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	தேர்வு (type) {
	நிலை SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		நிறுத்து;
	நிலை SSH2_FXP_EXTENDED:
		எனில் (!init_done)
			fatal("Received extended request before init");
		எனில் ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		நிறுத்து;
	இயல்பு:
		எனில் (!init_done)
			fatal("Received %u request before init", type);
		எனில் ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		க்கு (i = 0; handlers[i].handler != வெற்று; i++) {
			எனில் (type == handlers[i].type) {
				எனில் (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} இல்லையெனில் {
					handlers[i].handler(id);
				}
				நிறுத்து;
			}
		}
		எனில் (handlers[i].handler == வெற்று)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	எனில் (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	எனில் (செய்தி_len < consumed) {
		error("msg_len %u < consumed %u", செய்தி_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	எனில் (செய்தி_len > consumed &&
	    (r = sshbuf_consume(iqueue, செய்தி_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
வெறுமை
sftp_server_cleanup_exit(முழு i)
{
	எனில் (pw != வெற்று && client_addr != வெற்று) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

நிலையான வெறுமை
sftp_server_usage(வெறுமை)
{
	வெளி எழுத்து *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

முழு
sftp_server_main(முழு argc, எழுத்து **argv, கட்டமைப்பு passwd *user_pw)
{
	முழு i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	எழுத்து *cp, *homedir = வெற்று, uidstr[32], buf[4*4096];
	long mask;

	வெளி எழுத்து *optarg;
	வெளி எழுத்து *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	போது (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		தேர்வு (ch) {
		நிலை 'Q':
			எனில் (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			க்கு (i = 0; handlers[i].handler != வெற்று; i++)
				printf("%s\n", handlers[i].name);
			க்கு (i = 0; extended_handlers[i].handler != வெற்று; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			நிறுத்து;
		நிலை 'R':
			readonly = 1;
			நிறுத்து;
		நிலை 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			நிறுத்து;
		நிலை 'e':
			log_stderr = 1;
			நிறுத்து;
		நிலை 'l':
			log_level = log_level_எண்(optarg);
			எனில் (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			நிறுத்து;
		நிலை 'f':
			log_facility = log_facility_எண்(optarg);
			எனில் (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			நிறுத்து;
		நிலை 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, அளவு(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (எழுத்து *)வெற்று);
			விடுவி(cp);
			நிறுத்து;
		நிலை 'p':
			எனில் (request_allowlist != வெற்று)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			நிறுத்து;
		நிலை 'P':
			எனில் (request_denylist != வெற்று)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			நிறுத்து;
		நிலை 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			எனில் (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(வெறுமை)umask((mode_t)mask);
			நிறுத்து;
		நிலை 'h':
		இயல்பு:
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

	எனில் ((cp = getenv("SSH_CONNECTION")) != வெற்று) {
		client_addr = xstrdup(cp);
		எனில் ((cp = strchr(client_addr, ' ')) == வெற்று) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} இல்லையெனில்
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_இருமம்);
	setmode(out, O_இருமம்);
#endif

	எனில் ((iqueue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((oqueue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	எனில் (homedir != வெற்று) {
		எனில் (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	க்கு (;;) {
		கட்டமைப்பு pollfd pfd[2];

		memset(pfd, 0, அளவு pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		எனில் ((r = sshbuf_check_reserve(iqueue, அளவு(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_செய்தி_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		இல்லையெனில் எனில் (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		எனில் (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		எனில் (poll(pfd, 2, -1) == -1) {
			எனில் (errno == EINTR)
				தொடர்;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		எனில் (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = பட(in, buf, அளவு buf);
			எனில் (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} இல்லையெனில் எனில் (len == -1) {
				எனில் (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} இல்லையெனில் எனில் ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		எனில் (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = லிக(out, sshbuf_ptr(oqueue), olen);
			எனில் (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} இல்லையெனில் எனில் (len == -1) {
				sftp_server_cleanup_exit(1);
				எனில் (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} இல்லையெனில் எனில் ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_செய்தி_LENGTH);
		எனில் (r == 0)
			process();
		இல்லையெனில் எனில் (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
