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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/resource.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/statvfs.h>

#شامل <dirent.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <poll.h>
#شامل <pwd.h>
#شامل <grp.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <stdarg.h>

#شامل "atomicio.h"
#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "match.h"
#شامل "uidswap.h"

#شامل "sftp.h"
#شامل "sftp-common.h"

نویسه *sftp_realpath(ثابت نویسه *, نویسه *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_پیام_LENGTH - 1024)

/* Our verbosity */
ایستا LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ایستا ساختار passwd *pw = پوچ;
ایستا نویسه *client_addr = پوچ;

/* input and output queue */
ساختار sshbuf *iqueue;
ساختار sshbuf *oqueue;

/* Version of client */
ایستا u_int version;

/* SSH2_FXP_INIT received */
ایستا صحیح init_done;

/* Disable writes */
ایستا صحیح readonly;

/* Requests that are allowed/denied */
ایستا نویسه *request_allowlist, *request_denylist;

/* portable attributes, etc. */
تعریفنوع ساختار Stat Stat;

ساختار Stat {
	نویسه *name;
	نویسه *long_name;
	Attrib attrib;
};

/* Packet handlers */
ایستا تهی process_open(uint32_t id);
ایستا تهی process_close(uint32_t id);
ایستا تهی process_read(uint32_t id);
ایستا تهی process_write(uint32_t id);
ایستا تهی process_stat(uint32_t id);
ایستا تهی process_lstat(uint32_t id);
ایستا تهی process_fstat(uint32_t id);
ایستا تهی process_setstat(uint32_t id);
ایستا تهی process_fsetstat(uint32_t id);
ایستا تهی process_opendir(uint32_t id);
ایستا تهی process_readdir(uint32_t id);
ایستا تهی process_remove(uint32_t id);
ایستا تهی process_mkdir(uint32_t id);
ایستا تهی process_rmdir(uint32_t id);
ایستا تهی process_realpath(uint32_t id);
ایستا تهی process_rename(uint32_t id);
ایستا تهی process_readlink(uint32_t id);
ایستا تهی process_symlink(uint32_t id);
ایستا تهی process_extended_posix_rename(uint32_t id);
ایستا تهی process_extended_statvfs(uint32_t id);
ایستا تهی process_extended_fstatvfs(uint32_t id);
ایستا تهی process_extended_hardlink(uint32_t id);
ایستا تهی process_extended_fsync(uint32_t id);
ایستا تهی process_extended_lsetstat(uint32_t id);
ایستا تهی process_extended_limits(uint32_t id);
ایستا تهی process_extended_expand(uint32_t id);
ایستا تهی process_extended_copy_data(uint32_t id);
ایستا تهی process_extended_home_directory(uint32_t id);
ایستا تهی process_extended_get_users_groups_by_id(uint32_t id);
ایستا تهی process_extended(uint32_t id);

ساختار sftp_handler {
	ثابت نویسه *name;	/* user-visible name for fine-grained perms */
	ثابت نویسه *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	تهی (*handler)(uint32_t);
	صحیح does_write;		/* if nonzero, banned for readonly mode */
};

ایستا ثابت ساختار sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", پوچ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", پوچ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", پوچ, SSH2_FXP_READ, process_read, 0 },
	{ "write", پوچ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", پوچ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", پوچ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", پوچ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", پوچ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", پوچ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", پوچ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", پوچ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", پوچ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", پوچ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", پوچ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", پوچ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", پوچ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", پوچ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", پوچ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ پوچ, پوچ, 0, پوچ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ایستا ثابت ساختار sftp_handler extended_handlers[] = {
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
	{ پوچ, پوچ, 0, پوچ, 0 }
};

ایستا ثابت ساختار sftp_handler *
extended_handler_byname(ثابت نویسه *name)
{
	صحیح i;

	برای (i = 0; extended_handlers[i].handler != پوچ; i++) {
		اگر (strcmp(name, extended_handlers[i].ext_name) == 0)
			بازگشت &extended_handlers[i];
	}
	بازگشت پوچ;
}

ایستا صحیح
request_permitted(ثابت ساختار sftp_handler *h)
{
	نویسه *result;

	اگر (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		بازگشت 0;
	}
	اگر (request_denylist != پوچ &&
	    ((result = match_list(h->name, request_denylist, پوچ))) != پوچ) {
		آزاد(result);
		verbose("Refusing denylisted %s request", h->name);
		بازگشت 0;
	}
	اگر (request_allowlist != پوچ &&
	    ((result = match_list(h->name, request_allowlist, پوچ))) != پوچ) {
		آزاد(result);
		debug2("Permitting allowlisted %s request", h->name);
		بازگشت 1;
	}
	اگر (request_allowlist != پوچ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		بازگشت 0;
	}
	بازگشت 1;
}

ایستا صحیح
errno_to_portable(صحیح unixerrno)
{
	صحیح ret = 0;

	انتخاب (unixerrno) {
	حالت 0:
		ret = SSH2_FX_OK;
		بشکن;
	حالت ENOENT:
	حالت ENOTDIR:
	حالت EBADF:
	حالت ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		بشکن;
	حالت EPERM:
	حالت EACCES:
	حالت EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		بشکن;
	حالت ENAMETOOLONG:
	حالت EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		بشکن;
	حالت ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		بشکن;
	پیشفرض:
		ret = SSH2_FX_FAILURE;
		بشکن;
	}
	بازگشت ret;
}

ایستا صحیح
flags_from_portable(صحیح pflags)
{
	صحیح flags = 0;

	اگر ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} وگرنه اگر (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} وگرنه اگر (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	اگر (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	اگر (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	اگر (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	اگر (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	بازگشت flags;
}

ایستا ثابت نویسه *
string_from_portable(صحیح pflags)
{
	ایستا نویسه ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		اگر (*ret != '\0')			\
			strlcat(ret, ",", اندازه(ret));	\
		strlcat(ret, str, اندازه(ret));		\
	}

	اگر (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	اگر (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	اگر (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	اگر (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	اگر (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	اگر (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	بازگشت ret;
}

/* handle handles */

تعریفنوع ساختار Handle Handle;
ساختار Handle {
	صحیح use;
	DIR *dirp;
	صحیح fd;
	صحیح flags;
	نویسه *name;
	uint64_t bytes_read, bytes_write;
	صحیح next_unused;
};

شمارش {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

ایستا Handle *handles = پوچ;
ایستا u_int رقم_handles = 0;
ایستا صحیح first_unused_handle = -1;

ایستا تهی handle_unused(صحیح i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

ایستا صحیح
handle_new(صحیح use, ثابت نویسه *name, صحیح fd, صحیح flags, DIR *dirp)
{
	صحیح i;

	اگر (first_unused_handle == -1) {
		اگر (رقم_handles + 1 <= رقم_handles)
			بازگشت -1;
		رقم_handles++;
		handles = xreallocarray(handles, رقم_handles, اندازه(Handle));
		handle_unused(رقم_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	بازگشت i;
}

ایستا صحیح
handle_is_ok(صحیح i, صحیح type)
{
	بازگشت i >= 0 && (u_int)i < رقم_handles && handles[i].use == type;
}

ایستا صحیح
handle_to_string(صحیح handle, u_char **stringp, صحیح *hlenp)
{
	اگر (stringp == پوچ || hlenp == پوچ)
		بازگشت -1;
	*stringp = xmalloc(اندازه(int32_t));
	put_u32(*stringp, handle);
	*hlenp = اندازه(int32_t);
	بازگشت 0;
}

ایستا صحیح
handle_from_string(ثابت u_char *handle, u_int hlen)
{
	صحیح val;

	اگر (hlen != اندازه(int32_t))
		بازگشت -1;
	val = get_u32(handle);
	اگر (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		بازگشت val;
	بازگشت -1;
}

ایستا نویسه *
handle_to_name(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		بازگشت handles[handle].name;
	بازگشت پوچ;
}

ایستا DIR *
handle_to_dir(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_DIR))
		بازگشت handles[handle].dirp;
	بازگشت پوچ;
}

ایستا صحیح
handle_to_fd(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		بازگشت handles[handle].fd;
	بازگشت -1;
}

ایستا صحیح
handle_to_flags(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		بازگشت handles[handle].flags;
	بازگشت 0;
}

ایستا تهی
handle_update_read(صحیح handle, ssize_t bytes)
{
	اگر (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

ایستا تهی
handle_update_write(صحیح handle, ssize_t bytes)
{
	اگر (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

ایستا uint64_t
handle_bytes_read(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		بازگشت (handles[handle].bytes_read);
	بازگشت 0;
}

ایستا uint64_t
handle_bytes_write(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		بازگشت (handles[handle].bytes_write);
	بازگشت 0;
}

ایستا صحیح
handle_close(صحیح handle)
{
	صحیح ret = -1;

	اگر (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		آزاد(handles[handle].name);
		handle_unused(handle);
	} وگرنه اگر (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		آزاد(handles[handle].name);
		handle_unused(handle);
	} وگرنه {
		errno = ENOENT;
	}
	بازگشت ret;
}

ایستا تهی
handle_log_close(صحیح handle, نویسه *emsg)
{
	اگر (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == پوچ ? "" : emsg, emsg == پوچ ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} وگرنه {
		logit("%s%sclosedir \"%s\"",
		    emsg == پوچ ? "" : emsg, emsg == پوچ ? "" : " ",
		    handle_to_name(handle));
	}
}

ایستا تهی
handle_log_exit(تهی)
{
	u_int i;

	برای (i = 0; i < رقم_handles; i++)
		اگر (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

ایستا صحیح
get_handle(ساختار sshbuf *queue, صحیح *hp)
{
	u_char *handle;
	صحیح r;
	size_t hlen;

	*hp = -1;
	اگر ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		بازگشت r;
	اگر (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	آزاد(handle);
	بازگشت 0;
}

/* send replies */

ایستا تهی
send_پیام(ساختار sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ایستا ثابت نویسه *
status_to_message(uint32_t status)
{
	ایستا ثابت نویسه * ثابت status_messages[] = {
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
	بازگشت (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

ایستا تهی
send_status_errmsg(uint32_t id, uint32_t status, ثابت نویسه *errmsg)
{
	ساختار sshbuf *پیام;
	صحیح r;

	debug3("request %u: sent status %u", id, status);
	اگر (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_u32(پیام, status)) != 0)
		fatal_fr(r, "compose");
	اگر (version >= 3) {
		اگر ((r = sshbuf_put_cstring(پیام, errmsg == پوچ ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(پیام, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, پوچ);
}

ایستا تهی
send_data_or_handle(نویسه type, uint32_t id, ثابت u_char *data, صحیح dlen)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, type)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_string(پیام, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
send_data(uint32_t id, ثابت u_char *data, صحیح dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

ایستا تهی
send_handle(uint32_t id, صحیح handle)
{
	u_char *string;
	صحیح hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	آزاد(string);
}

ایستا تهی
send_names(uint32_t id, صحیح شمار, ثابت Stat *stats)
{
	ساختار sshbuf *پیام;
	صحیح i, r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_u32(پیام, شمار)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, شمار);
	برای (i = 0; i < شمار; i++) {
		اگر ((r = sshbuf_put_cstring(پیام, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(پیام, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(پیام, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
send_attrib(uint32_t id, ثابت Attrib *a)
{
	ساختار sshbuf *پیام;
	صحیح r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = encode_attrib(پیام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
send_statvfs(uint32_t id, ساختار statvfs *st)
{
	ساختار sshbuf *پیام;
	uint64_t flag;
	صحیح r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(پیام, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(پیام, flag)) != 0 ||
	    (r = sshbuf_put_u64(پیام, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_پیام(پیام);
	sshbuf_free(پیام);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ایستا صحیح
compose_extension(ساختار sshbuf *پیام, ثابت نویسه *name, ثابت نویسه *ver)
{
	صحیح r;
	ثابت ساختار sftp_handler *exthnd;

	اگر ((exthnd = extended_handler_byname(name)) == پوچ)
		fatal_f("internal error: no handler for %s", name);
	اگر (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		بازگشت 0;
	}
	اگر ((r = sshbuf_put_cstring(پیام, name)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	بازگشت 0;
}

/* parse incoming */

ایستا تهی
process_init(تهی)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(پیام, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(پیام, "posix-rename@openssh.com", "1");
	compose_extension(پیام, "statvfs@openssh.com", "2");
	compose_extension(پیام, "fstatvfs@openssh.com", "2");
	compose_extension(پیام, "hardlink@openssh.com", "1");
	compose_extension(پیام, "fsync@openssh.com", "1");
	compose_extension(پیام, "lsetstat@openssh.com", "1");
	compose_extension(پیام, "limits@openssh.com", "1");
	compose_extension(پیام, "expand-path@openssh.com", "1");
	compose_extension(پیام, "copy-data", "1");
	compose_extension(پیام, "home-directory", "1");
	compose_extension(پیام, "users-groups-by-id@openssh.com", "1");

	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	نویسه *name;
	صحیح r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	اگر (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} وگرنه {
		fd = open(name, flags, mode);
		اگر (fd == -1) {
			status = errno_to_portable(errno);
		} وگرنه {
			handle = handle_new(HANDLE_FILE, name, fd, flags, پوچ);
			اگر (handle < 0) {
				close(fd);
			} وگرنه {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	اگر (status != SSH2_FX_OK)
		send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_close(uint32_t id)
{
	صحیح r, handle, ret, status = SSH2_FX_FAILURE;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, پوچ);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

ایستا تهی
process_read(uint32_t id)
{
	ایستا u_char *buf;
	ایستا size_t buflen;
	uint32_t len;
	صحیح r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	اگر ((fd = handle_to_fd(handle)) == -1)
		برو out;
	اگر (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	اگر (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		اگر ((buf = realloc(buf, len)) == پوچ)
			fatal_f("realloc failed");
		buflen = len;
	}
	اگر (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		برو out;
	}
	اگر (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} وگرنه اگر ((ret = اقرأ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		برو out;
	} وگرنه اگر (ret == 0) {
		status = SSH2_FX_EOF;
		برو out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	اگر (status != SSH2_FX_OK)
		send_status(id, status);
}

ایستا تهی
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	صحیح r, handle, fd, ret, status;
	u_char *data;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	اگر (fd < 0)
		status = SSH2_FX_FAILURE;
	وگرنه {
		اگر (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} وگرنه {
/* XXX ATOMICIO ? */
			ret = اكتب(fd, data, len);
			اگر (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} وگرنه اگر ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} وگرنه {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	آزاد(data);
}

ایستا تهی
process_do_stat(uint32_t id, صحیح do_lstat)
{
	Attrib a;
	ساختار stat st;
	نویسه *name;
	صحیح r, status = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	اگر (r == -1) {
		status = errno_to_portable(errno);
	} وگرنه {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	اگر (status != SSH2_FX_OK)
		send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ایستا تهی
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ایستا تهی
process_fstat(uint32_t id)
{
	Attrib a;
	ساختار stat st;
	صحیح fd, r, handle, status = SSH2_FX_FAILURE;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	اگر (fd >= 0) {
		r = fstat(fd, &st);
		اگر (r == -1) {
			status = errno_to_portable(errno);
		} وگرنه {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	اگر (status != SSH2_FX_OK)
		send_status(id, status);
}

ایستا ساختار timeval *
attrib_to_tv(ثابت Attrib *a)
{
	ایستا ساختار timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	بازگشت tv;
}

ایستا ساختار timespec *
attrib_to_ts(ثابت Attrib *a)
{
	ایستا ساختار timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	بازگشت ts;
}

ایستا تهی
process_setstat(uint32_t id)
{
	Attrib a;
	نویسه *name;
	صحیح r, status = SSH2_FX_OK;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	اگر (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		نویسه buf[64];
		time_t t = a.mtime;

		strftime(buf, اندازه(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_fsetstat(uint32_t id)
{
	Attrib a;
	صحیح handle, fd, r;
	صحیح status = SSH2_FX_OK;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	اگر (fd < 0)
		status = SSH2_FX_FAILURE;
	وگرنه {
		نویسه *name = handle_to_name(handle);

		اگر (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			اگر (r == -1)
				status = errno_to_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#وگرنه
			r = chmod(name, a.perm & 07777);
#endif
			اگر (r == -1)
				status = errno_to_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			نویسه buf[64];
			time_t t = a.mtime;

			strftime(buf, اندازه(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#وگرنه
			r = utimes(name, attrib_to_tv(&a));
#endif
			اگر (r == -1)
				status = errno_to_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#وگرنه
			r = chown(name, a.uid, a.gid);
#endif
			اگر (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

ایستا تهی
process_opendir(uint32_t id)
{
	DIR *dirp = پوچ;
	نویسه *path;
	صحیح r, handle, status = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &path, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	اگر (dirp == پوچ) {
		status = errno_to_portable(errno);
	} وگرنه {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		اگر (handle < 0) {
			closedir(dirp);
		} وگرنه {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	اگر (status != SSH2_FX_OK)
		send_status(id, status);
	آزاد(path);
}

ایستا تهی
process_readdir(uint32_t id)
{
	DIR *dirp;
	ساختار dirent *dp;
	نویسه *path;
	صحیح r, handle;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	اگر (dirp == پوچ || path == پوچ) {
		send_status(id, SSH2_FX_FAILURE);
	} وگرنه {
		ساختار stat st;
		نویسه *pathname;
		Stat *stats;
		صحیح nstats = 10, شمار = 0, i;

		stats = xcalloc(nstats, اندازه(Stat));
		وقتی ((dp = readdir(dirp)) != پوچ) {
			اگر (شمار >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, اندازه(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			آزاد(pathname);
			اگر (r == -1)
				ادامه;
			stat_to_attrib(&st, &(stats[شمار].attrib));
			stats[شمار].name = xstrdup(dp->d_name);
			stats[شمار].long_name = ls_file(dp->d_name, &st,
			    0, 0, پوچ, پوچ);
			شمار++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			اگر (شمار == 100)
				بشکن;
		}
		اگر (شمار > 0) {
			send_names(id, شمار, stats);
			برای (i = 0; i < شمار; i++) {
				آزاد(stats[i].name);
				آزاد(stats[i].long_name);
			}
		} وگرنه {
			send_status(id, SSH2_FX_EOF);
		}
		آزاد(stats);
	}
}

ایستا تهی
process_remove(uint32_t id)
{
	نویسه *name;
	صحیح r, status = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_mkdir(uint32_t id)
{
	Attrib a;
	نویسه *name;
	صحیح r, mode, status = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_rmdir(uint32_t id)
{
	نویسه *name;
	صحیح r, status;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_realpath(uint32_t id)
{
	نویسه resolvedname[PATH_MAX];
	نویسه *path;
	صحیح r;

	اگر ((r = sshbuf_get_cstring(iqueue, &path, پوچ)) != 0)
		fatal_fr(r, "parse");

	اگر (path[0] == '\0') {
		آزاد(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	اگر (sftp_realpath(path, resolvedname) == پوچ) {
		send_status(id, errno_to_portable(errno));
	} وگرنه {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	آزاد(path);
}

ایستا تهی
process_rename(uint32_t id)
{
	نویسه *oldpath, *newpath;
	صحیح r, status;
	ساختار stat sb;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	اگر (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	وگرنه اگر (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		اگر (link(oldpath, newpath) == -1) {
			اگر (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				ساختار stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				اگر (stat(newpath, &st) == -1) {
					اگر (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					وگرنه
						status = SSH2_FX_OK;
				}
			} وگرنه {
				status = errno_to_portable(errno);
			}
		} وگرنه اگر (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} وگرنه
			status = SSH2_FX_OK;
	} وگرنه اگر (stat(newpath, &sb) == -1) {
		اگر (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		وگرنه
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	آزاد(oldpath);
	آزاد(newpath);
}

ایستا تهی
process_readlink(uint32_t id)
{
	صحیح r, len;
	نویسه buf[PATH_MAX];
	نویسه *path;

	اگر ((r = sshbuf_get_cstring(iqueue, &path, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	اگر ((len = readlink(path, buf, اندازه(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	وگرنه {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	آزاد(path);
}

ایستا تهی
process_symlink(uint32_t id)
{
	نویسه *oldpath, *newpath;
	صحیح r, status;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(oldpath);
	آزاد(newpath);
}

ایستا تهی
process_extended_posix_rename(uint32_t id)
{
	نویسه *oldpath, *newpath;
	صحیح r, status;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(oldpath);
	آزاد(newpath);
}

ایستا تهی
process_extended_statvfs(uint32_t id)
{
	نویسه *path;
	ساختار statvfs st;
	صحیح r;

	اگر ((r = sshbuf_get_cstring(iqueue, &path, پوچ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	اگر (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	وگرنه
		send_statvfs(id, &st);
	آزاد(path);
}

ایستا تهی
process_extended_fstatvfs(uint32_t id)
{
	صحیح r, handle, fd;
	ساختار statvfs st;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	اگر ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		بازگشت;
	}
	اگر (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	وگرنه
		send_statvfs(id, &st);
}

ایستا تهی
process_extended_hardlink(uint32_t id)
{
	نویسه *oldpath, *newpath;
	صحیح r, status;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	آزاد(oldpath);
	آزاد(newpath);
}

ایستا تهی
process_extended_fsync(uint32_t id)
{
	صحیح handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	اگر ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	وگرنه اگر (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

ایستا تهی
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	نویسه *name;
	صحیح r, status = SSH2_FX_OK;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, پوچ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	اگر (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		برو out;
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		نویسه buf[64];
		time_t t = a.mtime;

		strftime(buf, اندازه(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	آزاد(name);
}

ایستا تهی
process_extended_limits(uint32_t id)
{
	ساختار sshbuf *پیام;
	صحیح r;
	uint64_t nfiles = 0;
#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ساختار rlimit rlim;
#endif

	debug("request %u: limits", id);

#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	اگر (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(پیام, SFTP_MAX_پیام_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(پیام, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(پیام, SFTP_MAX_پیام_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(پیام, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_پیام(پیام);
	sshbuf_free(پیام);
}

ایستا تهی
process_extended_expand(uint32_t id)
{
	نویسه cwd[PATH_MAX], resolvedname[PATH_MAX];
	نویسه *path, *npath;
	صحیح r;
	Stat s;

	اگر ((r = sshbuf_get_cstring(iqueue, &path, پوچ)) != 0)
		fatal_fr(r, "parse");
	اگر (getcwd(cwd, اندازه(cwd)) == پوچ) {
		send_status(id, errno_to_portable(errno));
		برو out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	اگر (path[0] == '\0') {
		/* empty path */
		آزاد(path);
		path = xstrdup(".");
	} وگرنه اگر (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		اگر (strcmp(path, "~") == 0) {
			آزاد(path);
			path = xstrdup(cwd);
		} وگرنه اگر (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			آزاد(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			آزاد(npath);
		} وگرنه {
			/* ~user expansions */
			اگر (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				برو out;
			}
			آزاد(path);
			path = npath;
		}
	} وگرنه اگر (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		آزاد(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	اگر (sftp_realpath(path, resolvedname) == پوچ) {
		send_status(id, errno_to_portable(errno));
		برو out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	آزاد(path);
}

ایستا تهی
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	صحیح read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	صحیح r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	ساختار stat st_read, st_write;

	اگر ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	اگر (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} وگرنه
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	اگر (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		برو out;
	}
	اگر (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		برو out;
	}
	اگر (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		برو out;
	}
	اگر (read_handle == write_handle ||
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
		برو out;
	}

	اگر (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		برو out;
	}

	اگر ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		برو out;
	}

	/* Process the request in chunks. */
	وقتی (read_len > 0 || copy_until_eof) {
		len = MINIMUM(اندازه(buf), read_len);
		read_len -= len;

		ret = atomicio(اقرأ, read_fd, buf, len);
		اگر (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			بشکن;
		} وگرنه اگر (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			بشکن;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		اگر (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			بشکن;
		}
		handle_update_write(write_handle, len);
	}

	اگر (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

ایستا تهی
process_extended_home_directory(uint32_t id)
{
	نویسه *username;
	ساختار passwd *user_pw;
	صحیح r;
	Stat s;

	اگر ((r = sshbuf_get_cstring(iqueue, &username, پوچ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	اگر (username[0] == '\0') {
		user_pw = pw;
	} وگرنه اگر ((user_pw = getpwnam(username)) == پوچ) {
		send_status(id, SSH2_FX_FAILURE);
		برو out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	آزاد(username);
}

ایستا تهی
process_extended_get_users_groups_by_id(uint32_t id)
{
	ساختار passwd *user_pw;
	ساختار group *gr;
	ساختار sshbuf *uids, *gids, *usernames, *groupnames, *پیام;
	صحیح r;
	u_int n, nusers = 0, ngroups = 0;
	ثابت نویسه *name;

	اگر ((usernames = sshbuf_new()) == پوچ ||
	    (groupnames = sshbuf_new()) == پوچ ||
	    (پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	وقتی (sshbuf_len(uids) != 0) {
		اگر ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == پوچ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		اگر ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	وقتی (sshbuf_len(gids) != 0) {
		اگر ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == پوچ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		اگر ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_پیام(پیام);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(پیام);
}

ایستا تهی
process_extended(uint32_t id)
{
	نویسه *request;
	صحیح r;
	ثابت ساختار sftp_handler *exthand;

	اگر ((r = sshbuf_get_cstring(iqueue, &request, پوچ)) != 0)
		fatal_fr(r, "parse");
	اگر ((exthand = extended_handler_byname(request)) == پوچ) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} وگرنه {
		اگر (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		وگرنه
			exthand->handler(id);
	}
	آزاد(request);
}

/* stolen from ssh-agent */

ایستا تهی
process(تهی)
{
	u_int پیام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحیح i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	اگر (buf_len < 5)
		بازگشت;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیام_len = get_u32(cp);
	اگر (پیام_len > SFTP_MAX_پیام_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	اگر (buf_len < پیام_len + 4)
		بازگشت;
	اگر ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	اگر ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	انتخاب (type) {
	حالت SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		بشکن;
	حالت SSH2_FXP_EXTENDED:
		اگر (!init_done)
			fatal("Received extended request before init");
		اگر ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		بشکن;
	پیشفرض:
		اگر (!init_done)
			fatal("Received %u request before init", type);
		اگر ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		برای (i = 0; handlers[i].handler != پوچ; i++) {
			اگر (type == handlers[i].type) {
				اگر (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} وگرنه {
					handlers[i].handler(id);
				}
				بشکن;
			}
		}
		اگر (handlers[i].handler == پوچ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	اگر (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	اگر (پیام_len < consumed) {
		error("msg_len %u < consumed %u", پیام_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	اگر (پیام_len > consumed &&
	    (r = sshbuf_consume(iqueue, پیام_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
تهی
sftp_server_cleanup_exit(صحیح i)
{
	اگر (pw != پوچ && client_addr != پوچ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ایستا تهی
sftp_server_usage(تهی)
{
	بیرونی نویسه *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

صحیح
sftp_server_main(صحیح argc, نویسه **argv, ساختار passwd *user_pw)
{
	صحیح i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	نویسه *cp, *homedir = پوچ, uidstr[32], buf[4*4096];
	long mask;

	بیرونی نویسه *optarg;
	بیرونی نویسه *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	وقتی (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		انتخاب (ch) {
		حالت 'Q':
			اگر (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			برای (i = 0; handlers[i].handler != پوچ; i++)
				printf("%s\n", handlers[i].name);
			برای (i = 0; extended_handlers[i].handler != پوچ; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			بشکن;
		حالت 'R':
			readonly = 1;
			بشکن;
		حالت 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			بشکن;
		حالت 'e':
			log_stderr = 1;
			بشکن;
		حالت 'l':
			log_level = log_level_عدد(optarg);
			اگر (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			بشکن;
		حالت 'f':
			log_facility = log_facility_عدد(optarg);
			اگر (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			بشکن;
		حالت 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, اندازه(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (نویسه *)پوچ);
			آزاد(cp);
			بشکن;
		حالت 'p':
			اگر (request_allowlist != پوچ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			بشکن;
		حالت 'P':
			اگر (request_denylist != پوچ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			بشکن;
		حالت 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			اگر (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(تهی)umask((mode_t)mask);
			بشکن;
		حالت 'h':
		پیشفرض:
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

	اگر ((cp = getenv("SSH_CONNECTION")) != پوچ) {
		client_addr = xstrdup(cp);
		اگر ((cp = strchr(client_addr, ' ')) == پوچ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} وگرنه
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_دودویی);
	setmode(out, O_دودویی);
#endif

	اگر ((iqueue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((oqueue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	اگر (homedir != پوچ) {
		اگر (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	برای (;;) {
		ساختار pollfd pfd[2];

		memset(pfd, 0, اندازه pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		اگر ((r = sshbuf_check_reserve(iqueue, اندازه(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_پیام_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		وگرنه اگر (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		اگر (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		اگر (poll(pfd, 2, -1) == -1) {
			اگر (errno == EINTR)
				ادامه;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		اگر (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = اقرأ(in, buf, اندازه buf);
			اگر (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} وگرنه اگر (len == -1) {
				اگر (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} وگرنه اگر ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		اگر (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = اكتب(out, sshbuf_ptr(oqueue), olen);
			اگر (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} وگرنه اگر (len == -1) {
				sftp_server_cleanup_exit(1);
				اگر (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} وگرنه اگر ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_پیام_LENGTH);
		اگر (r == 0)
			process();
		وگرنه اگر (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
