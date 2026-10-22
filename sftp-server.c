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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/resource.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/statvfs.h>

#ضمن <dirent.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <poll.h>
#ضمن <pwd.h>
#ضمن <grp.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>

#ضمن "atomicio.h"
#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "match.h"
#ضمن "uidswap.h"

#ضمن "sftp.h"
#ضمن "sftp-common.h"

حرف *sftp_realpath(ثابت حرف *, حرف *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_MSG_LENGTH - 1024)

/* Our verbosity */
ساكن LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ساكن بنية passwd *pw = عدم;
ساكن حرف *client_addr = عدم;

/* input and output queue */
بنية sshbuf *iqueue;
بنية sshbuf *oqueue;

/* Version of client */
ساكن u_int version;

/* SSH2_FXP_INIT received */
ساكن صحيح init_done;

/* Disable writes */
ساكن صحيح readonly;

/* Requests that are allowed/denied */
ساكن حرف *request_allowlist, *request_denylist;

/* portable attributes, etc. */
تعريفنوع بنية Stat Stat;

بنية Stat {
	حرف *name;
	حرف *long_name;
	Attrib attrib;
};

/* Packet handlers */
ساكن فراغ process_open(uint32_t id);
ساكن فراغ process_close(uint32_t id);
ساكن فراغ process_read(uint32_t id);
ساكن فراغ process_write(uint32_t id);
ساكن فراغ process_stat(uint32_t id);
ساكن فراغ process_lstat(uint32_t id);
ساكن فراغ process_fstat(uint32_t id);
ساكن فراغ process_setstat(uint32_t id);
ساكن فراغ process_fsetstat(uint32_t id);
ساكن فراغ process_opendir(uint32_t id);
ساكن فراغ process_readdir(uint32_t id);
ساكن فراغ process_remove(uint32_t id);
ساكن فراغ process_mkdir(uint32_t id);
ساكن فراغ process_rmdir(uint32_t id);
ساكن فراغ process_realpath(uint32_t id);
ساكن فراغ process_rename(uint32_t id);
ساكن فراغ process_readlink(uint32_t id);
ساكن فراغ process_symlink(uint32_t id);
ساكن فراغ process_extended_posix_rename(uint32_t id);
ساكن فراغ process_extended_statvfs(uint32_t id);
ساكن فراغ process_extended_fstatvfs(uint32_t id);
ساكن فراغ process_extended_hardlink(uint32_t id);
ساكن فراغ process_extended_fsync(uint32_t id);
ساكن فراغ process_extended_lsetstat(uint32_t id);
ساكن فراغ process_extended_limits(uint32_t id);
ساكن فراغ process_extended_expand(uint32_t id);
ساكن فراغ process_extended_copy_data(uint32_t id);
ساكن فراغ process_extended_home_directory(uint32_t id);
ساكن فراغ process_extended_get_users_groups_by_id(uint32_t id);
ساكن فراغ process_extended(uint32_t id);

بنية sftp_handler {
	ثابت حرف *name;	/* user-visible name for fine-grained perms */
	ثابت حرف *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	فراغ (*handler)(uint32_t);
	صحيح does_write;		/* if nonzero, banned for readonly mode */
};

ساكن ثابت بنية sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", عدم, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", عدم, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", عدم, SSH2_FXP_READ, process_read, 0 },
	{ "write", عدم, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", عدم, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", عدم, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", عدم, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", عدم, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", عدم, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", عدم, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", عدم, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", عدم, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", عدم, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", عدم, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", عدم, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", عدم, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", عدم, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", عدم, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ عدم, عدم, 0, عدم, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ساكن ثابت بنية sftp_handler extended_handlers[] = {
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
	{ عدم, عدم, 0, عدم, 0 }
};

ساكن ثابت بنية sftp_handler *
extended_handler_byname(ثابت حرف *name)
{
	صحيح i;

	עבור (i = 0; extended_handlers[i].handler != عدم; i++) {
		אם (strcmp(name, extended_handlers[i].ext_name) == 0)
			החזר &extended_handlers[i];
	}
	החזר عدم;
}

ساكن صحيح
request_permitted(ثابت بنية sftp_handler *h)
{
	حرف *result;

	אם (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		החזר 0;
	}
	אם (request_denylist != عدم &&
	    ((result = match_list(h->name, request_denylist, عدم))) != عدم) {
		حرر(result);
		verbose("Refusing denylisted %s request", h->name);
		החזר 0;
	}
	אם (request_allowlist != عدم &&
	    ((result = match_list(h->name, request_allowlist, عدم))) != عدم) {
		حرر(result);
		debug2("Permitting allowlisted %s request", h->name);
		החזר 1;
	}
	אם (request_allowlist != عدم) {
		verbose("Refusing non-allowlisted %s request", h->name);
		החזר 0;
	}
	החזר 1;
}

ساكن صحيح
errno_to_portable(صحيح unixerrno)
{
	صحيح ret = 0;

	بدل (unixerrno) {
	حالة 0:
		ret = SSH2_FX_OK;
		اكسر;
	حالة ENOENT:
	حالة ENOTDIR:
	حالة EBADF:
	حالة ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		اكسر;
	حالة EPERM:
	حالة EACCES:
	حالة EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		اكسر;
	حالة ENAMETOOLONG:
	حالة EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		اكسر;
	حالة ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		اكسر;
	افتراضي:
		ret = SSH2_FX_FAILURE;
		اكسر;
	}
	החזר ret;
}

ساكن صحيح
flags_from_portable(صحيح pflags)
{
	صحيح flags = 0;

	אם ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} אחרת אם (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} אחרת אם (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	אם (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	אם (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	אם (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	אם (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	החזר flags;
}

ساكن ثابت حرف *
string_from_portable(صحيح pflags)
{
	ساكن حرف ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		אם (*ret != '\0')			\
			strlcat(ret, ",", حجم(ret));	\
		strlcat(ret, str, حجم(ret));		\
	}

	אם (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	אם (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	אם (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	אם (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	אם (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	אם (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	החזר ret;
}

/* handle handles */

تعريفنوع بنية Handle Handle;
بنية Handle {
	صحيح use;
	DIR *dirp;
	صحيح fd;
	صحيح flags;
	حرف *name;
	uint64_t bytes_read, bytes_write;
	صحيح next_unused;
};

تعداد {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

ساكن Handle *handles = عدم;
ساكن u_int num_handles = 0;
ساكن صحيح first_unused_handle = -1;

ساكن فراغ handle_unused(صحيح i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

ساكن صحيح
handle_new(صحيح use, ثابت حرف *name, صحيح fd, صحيح flags, DIR *dirp)
{
	صحيح i;

	אם (first_unused_handle == -1) {
		אם (num_handles + 1 <= num_handles)
			החזר -1;
		num_handles++;
		handles = xreallocarray(handles, num_handles, حجم(Handle));
		handle_unused(num_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	החזר i;
}

ساكن صحيح
handle_is_ok(صحيح i, صحيح type)
{
	החזר i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

ساكن صحيح
handle_to_string(صحيح handle, u_char **stringp, صحيح *hlenp)
{
	אם (stringp == عدم || hlenp == عدم)
		החזר -1;
	*stringp = xmalloc(حجم(int32_t));
	put_u32(*stringp, handle);
	*hlenp = حجم(int32_t);
	החזר 0;
}

ساكن صحيح
handle_from_string(ثابت u_char *handle, u_int hlen)
{
	صحيح val;

	אם (hlen != حجم(int32_t))
		החזר -1;
	val = get_u32(handle);
	אם (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		החזר val;
	החזר -1;
}

ساكن حرف *
handle_to_name(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		החזר handles[handle].name;
	החזר عدم;
}

ساكن DIR *
handle_to_dir(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_DIR))
		החזר handles[handle].dirp;
	החזר عدم;
}

ساكن صحيح
handle_to_fd(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_FILE))
		החזר handles[handle].fd;
	החזר -1;
}

ساكن صحيح
handle_to_flags(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_FILE))
		החזר handles[handle].flags;
	החזר 0;
}

ساكن فراغ
handle_update_read(صحيح handle, ssize_t bytes)
{
	אם (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

ساكن فراغ
handle_update_write(صحيح handle, ssize_t bytes)
{
	אם (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

ساكن uint64_t
handle_bytes_read(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_FILE))
		החזר (handles[handle].bytes_read);
	החזר 0;
}

ساكن uint64_t
handle_bytes_write(صحيح handle)
{
	אם (handle_is_ok(handle, HANDLE_FILE))
		החזר (handles[handle].bytes_write);
	החזר 0;
}

ساكن صحيح
handle_close(صحيح handle)
{
	صحيح ret = -1;

	אם (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		حرر(handles[handle].name);
		handle_unused(handle);
	} אחרת אם (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		حرر(handles[handle].name);
		handle_unused(handle);
	} אחרת {
		errno = ENOENT;
	}
	החזר ret;
}

ساكن فراغ
handle_log_close(صحيح handle, حرف *emsg)
{
	אם (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == عدم ? "" : emsg, emsg == عدم ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} אחרת {
		logit("%s%sclosedir \"%s\"",
		    emsg == عدم ? "" : emsg, emsg == عدم ? "" : " ",
		    handle_to_name(handle));
	}
}

ساكن فراغ
handle_log_exit(فراغ)
{
	u_int i;

	עבור (i = 0; i < num_handles; i++)
		אם (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

ساكن صحيح
get_handle(بنية sshbuf *queue, صحيح *hp)
{
	u_char *handle;
	صحيح r;
	size_t hlen;

	*hp = -1;
	אם ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		החזר r;
	אם (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	حرر(handle);
	החזר 0;
}

/* send replies */

ساكن فراغ
send_msg(بنية sshbuf *m)
{
	صحيح r;

	אם ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ساكن ثابت حرف *
status_to_message(uint32_t status)
{
	ساكن ثابت حرف * ثابت status_messages[] = {
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
	החזר (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

ساكن فراغ
send_status_errmsg(uint32_t id, uint32_t status, ثابت حرف *errmsg)
{
	بنية sshbuf *msg;
	صحيح r;

	debug3("request %u: sent status %u", id, status);
	אם (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal_fr(r, "compose");
	אם (version >= 3) {
		אם ((r = sshbuf_put_cstring(msg, errmsg == عدم ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, عدم);
}

ساكن فراغ
send_data_or_handle(حرف type, uint32_t id, ثابت u_char *data, صحيح dlen)
{
	بنية sshbuf *msg;
	صحيح r;

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
send_data(uint32_t id, ثابت u_char *data, صحيح dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

ساكن فراغ
send_handle(uint32_t id, صحيح handle)
{
	u_char *string;
	صحيح hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	حرر(string);
}

ساكن فراغ
send_names(uint32_t id, صحيح count, ثابت Stat *stats)
{
	بنية sshbuf *msg;
	صحيح i, r;

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, count);
	עבור (i = 0; i < count; i++) {
		אם ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(msg, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(msg, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
send_attrib(uint32_t id, ثابت Attrib *a)
{
	بنية sshbuf *msg;
	صحيح r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
send_statvfs(uint32_t id, بنية statvfs *st)
{
	بنية sshbuf *msg;
	uint64_t flag;
	صحيح r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(msg, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(msg, flag)) != 0 ||
	    (r = sshbuf_put_u64(msg, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ساكن صحيح
compose_extension(بنية sshbuf *msg, ثابت حرف *name, ثابت حرف *ver)
{
	صحيح r;
	ثابت بنية sftp_handler *exthnd;

	אם ((exthnd = extended_handler_byname(name)) == عدم)
		fatal_f("internal error: no handler for %s", name);
	אם (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		החזר 0;
	}
	אם ((r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	החזר 0;
}

/* parse incoming */

ساكن فراغ
process_init(فراغ)
{
	بنية sshbuf *msg;
	صحيح r;

	אם ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(msg, "posix-rename@openssh.com", "1");
	compose_extension(msg, "statvfs@openssh.com", "2");
	compose_extension(msg, "fstatvfs@openssh.com", "2");
	compose_extension(msg, "hardlink@openssh.com", "1");
	compose_extension(msg, "fsync@openssh.com", "1");
	compose_extension(msg, "lsetstat@openssh.com", "1");
	compose_extension(msg, "limits@openssh.com", "1");
	compose_extension(msg, "expand-path@openssh.com", "1");
	compose_extension(msg, "copy-data", "1");
	compose_extension(msg, "home-directory", "1");
	compose_extension(msg, "users-groups-by-id@openssh.com", "1");

	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	حرف *name;
	صحيح r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	אם (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} אחרת {
		fd = open(name, flags, mode);
		אם (fd == -1) {
			status = errno_to_portable(errno);
		} אחרת {
			handle = handle_new(HANDLE_FILE, name, fd, flags, عدم);
			אם (handle < 0) {
				close(fd);
			} אחרת {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	אם (status != SSH2_FX_OK)
		send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_close(uint32_t id)
{
	صحيح r, handle, ret, status = SSH2_FX_FAILURE;

	אם ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, عدم);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

ساكن فراغ
process_read(uint32_t id)
{
	ساكن u_char *buf;
	ساكن size_t buflen;
	uint32_t len;
	صحيح r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	אם ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	אם ((fd = handle_to_fd(handle)) == -1)
		اذهب out;
	אם (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	אם (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		אם ((buf = realloc(buf, len)) == عدم)
			fatal_f("realloc failed");
		buflen = len;
	}
	אם (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		اذهب out;
	}
	אם (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} אחרת אם ((ret = اقرأ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		اذهب out;
	} אחרת אם (ret == 0) {
		status = SSH2_FX_EOF;
		اذهب out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	אם (status != SSH2_FX_OK)
		send_status(id, status);
}

ساكن فراغ
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	صحيح r, handle, fd, ret, status;
	u_char *data;

	אם ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	אם (fd < 0)
		status = SSH2_FX_FAILURE;
	אחרת {
		אם (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} אחרת {
/* XXX ATOMICIO ? */
			ret = اكتب(fd, data, len);
			אם (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} אחרת אם ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} אחרת {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	حرر(data);
}

ساكن فراغ
process_do_stat(uint32_t id, صحيح do_lstat)
{
	Attrib a;
	بنية stat st;
	حرف *name;
	صحيح r, status = SSH2_FX_FAILURE;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	אם (r == -1) {
		status = errno_to_portable(errno);
	} אחרת {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	אם (status != SSH2_FX_OK)
		send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ساكن فراغ
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ساكن فراغ
process_fstat(uint32_t id)
{
	Attrib a;
	بنية stat st;
	صحيح fd, r, handle, status = SSH2_FX_FAILURE;

	אם ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	אם (fd >= 0) {
		r = fstat(fd, &st);
		אם (r == -1) {
			status = errno_to_portable(errno);
		} אחרת {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	אם (status != SSH2_FX_OK)
		send_status(id, status);
}

ساكن بنية timeval *
attrib_to_tv(ثابت Attrib *a)
{
	ساكن بنية timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	החזר tv;
}

ساكن بنية timespec *
attrib_to_ts(ثابت Attrib *a)
{
	ساكن بنية timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	החזר ts;
}

ساكن فراغ
process_setstat(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحيح r, status = SSH2_FX_OK;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	אם (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		حرف buf[64];
		time_t t = a.mtime;

		strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_fsetstat(uint32_t id)
{
	Attrib a;
	صحيح handle, fd, r;
	صحيح status = SSH2_FX_OK;

	אם ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	אם (fd < 0)
		status = SSH2_FX_FAILURE;
	אחרת {
		حرف *name = handle_to_name(handle);

		אם (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			אם (r == -1)
				status = errno_to_portable(errno);
		}
		אם (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#אחרת
			r = chmod(name, a.perm & 07777);
#endif
			אם (r == -1)
				status = errno_to_portable(errno);
		}
		אם (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			حرف buf[64];
			time_t t = a.mtime;

			strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#אחרת
			r = utimes(name, attrib_to_tv(&a));
#endif
			אם (r == -1)
				status = errno_to_portable(errno);
		}
		אם (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#אחרת
			r = chown(name, a.uid, a.gid);
#endif
			אם (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

ساكن فراغ
process_opendir(uint32_t id)
{
	DIR *dirp = عدم;
	حرف *path;
	صحيح r, handle, status = SSH2_FX_FAILURE;

	אם ((r = sshbuf_get_cstring(iqueue, &path, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	אם (dirp == عدم) {
		status = errno_to_portable(errno);
	} אחרת {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		אם (handle < 0) {
			closedir(dirp);
		} אחרת {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	אם (status != SSH2_FX_OK)
		send_status(id, status);
	حرر(path);
}

ساكن فراغ
process_readdir(uint32_t id)
{
	DIR *dirp;
	بنية dirent *dp;
	حرف *path;
	صحيح r, handle;

	אם ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	אם (dirp == عدم || path == عدم) {
		send_status(id, SSH2_FX_FAILURE);
	} אחרת {
		بنية stat st;
		حرف *pathname;
		Stat *stats;
		صحيح nstats = 10, count = 0, i;

		stats = xcalloc(nstats, حجم(Stat));
		כלעוד ((dp = readdir(dirp)) != عدم) {
			אם (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, حجم(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			حرر(pathname);
			אם (r == -1)
				استمر;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st,
			    0, 0, عدم, عدم);
			count++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			אם (count == 100)
				اكسر;
		}
		אם (count > 0) {
			send_names(id, count, stats);
			עבור (i = 0; i < count; i++) {
				حرر(stats[i].name);
				حرر(stats[i].long_name);
			}
		} אחרת {
			send_status(id, SSH2_FX_EOF);
		}
		حرر(stats);
	}
}

ساكن فراغ
process_remove(uint32_t id)
{
	حرف *name;
	صحيح r, status = SSH2_FX_FAILURE;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_mkdir(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحيح r, mode, status = SSH2_FX_FAILURE;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_rmdir(uint32_t id)
{
	حرف *name;
	صحيح r, status;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_realpath(uint32_t id)
{
	حرف resolvedname[PATH_MAX];
	حرف *path;
	صحيح r;

	אם ((r = sshbuf_get_cstring(iqueue, &path, عدم)) != 0)
		fatal_fr(r, "parse");

	אם (path[0] == '\0') {
		حرر(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	אם (sftp_realpath(path, resolvedname) == عدم) {
		send_status(id, errno_to_portable(errno));
	} אחרת {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	حرر(path);
}

ساكن فراغ
process_rename(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحيح r, status;
	بنية stat sb;

	אם ((r = sshbuf_get_cstring(iqueue, &oldpath, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	אם (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	אחרת אם (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		אם (link(oldpath, newpath) == -1) {
			אם (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				بنية stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				אם (stat(newpath, &st) == -1) {
					אם (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					אחרת
						status = SSH2_FX_OK;
				}
			} אחרת {
				status = errno_to_portable(errno);
			}
		} אחרת אם (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} אחרת
			status = SSH2_FX_OK;
	} אחרת אם (stat(newpath, &sb) == -1) {
		אם (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		אחרת
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	حرر(oldpath);
	حرر(newpath);
}

ساكن فراغ
process_readlink(uint32_t id)
{
	صحيح r, len;
	حرف buf[PATH_MAX];
	حرف *path;

	אם ((r = sshbuf_get_cstring(iqueue, &path, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	אם ((len = readlink(path, buf, حجم(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	אחרת {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	حرر(path);
}

ساكن فراغ
process_symlink(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحيح r, status;

	אם ((r = sshbuf_get_cstring(iqueue, &oldpath, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(oldpath);
	حرر(newpath);
}

ساكن فراغ
process_extended_posix_rename(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحيح r, status;

	אם ((r = sshbuf_get_cstring(iqueue, &oldpath, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(oldpath);
	حرر(newpath);
}

ساكن فراغ
process_extended_statvfs(uint32_t id)
{
	حرف *path;
	بنية statvfs st;
	صحيح r;

	אם ((r = sshbuf_get_cstring(iqueue, &path, عدم)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	אם (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	אחרת
		send_statvfs(id, &st);
	حرر(path);
}

ساكن فراغ
process_extended_fstatvfs(uint32_t id)
{
	صحيح r, handle, fd;
	بنية statvfs st;

	אם ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	אם ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		החזר;
	}
	אם (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	אחרת
		send_statvfs(id, &st);
}

ساكن فراغ
process_extended_hardlink(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحيح r, status;

	אם ((r = sshbuf_get_cstring(iqueue, &oldpath, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	حرر(oldpath);
	حرر(newpath);
}

ساكن فراغ
process_extended_fsync(uint32_t id)
{
	صحيح handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	אם ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	אם ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	אחרת אם (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

ساكن فراغ
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحيح r, status = SSH2_FX_OK;

	אם ((r = sshbuf_get_cstring(iqueue, &name, عدم)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	אם (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		اذهب out;
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		حرف buf[64];
		time_t t = a.mtime;

		strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
	אם (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		אם (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	حرر(name);
}

ساكن فراغ
process_extended_limits(uint32_t id)
{
	بنية sshbuf *msg;
	صحيح r;
	uint64_t nfiles = 0;
#אם defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	بنية rlimit rlim;
#endif

	debug("request %u: limits", id);

#אם defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	אם (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(msg, SFTP_MAX_MSG_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(msg, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(msg, SFTP_MAX_MSG_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(msg, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

ساكن فراغ
process_extended_expand(uint32_t id)
{
	حرف cwd[PATH_MAX], resolvedname[PATH_MAX];
	حرف *path, *npath;
	صحيح r;
	Stat s;

	אם ((r = sshbuf_get_cstring(iqueue, &path, عدم)) != 0)
		fatal_fr(r, "parse");
	אם (getcwd(cwd, حجم(cwd)) == عدم) {
		send_status(id, errno_to_portable(errno));
		اذهب out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	אם (path[0] == '\0') {
		/* empty path */
		حرر(path);
		path = xstrdup(".");
	} אחרת אם (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		אם (strcmp(path, "~") == 0) {
			حرر(path);
			path = xstrdup(cwd);
		} אחרת אם (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			حرر(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			حرر(npath);
		} אחרת {
			/* ~user expansions */
			אם (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				اذهب out;
			}
			حرر(path);
			path = npath;
		}
	} אחרת אם (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		حرر(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	אם (sftp_realpath(path, resolvedname) == عدم) {
		send_status(id, errno_to_portable(errno));
		اذهب out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	حرر(path);
}

ساكن فراغ
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	صحيح read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	صحيح r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	بنية stat st_read, st_write;

	אם ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	אם (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} אחרת
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	אם (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		اذهب out;
	}
	אם (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		اذهب out;
	}
	אם (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		اذهب out;
	}
	אם (read_handle == write_handle ||
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
		اذهب out;
	}

	אם (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		اذهب out;
	}

	אם ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		اذهب out;
	}

	/* Process the request in chunks. */
	כלעוד (read_len > 0 || copy_until_eof) {
		len = MINIMUM(حجم(buf), read_len);
		read_len -= len;

		ret = atomicio(اقرأ, read_fd, buf, len);
		אם (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			اكسر;
		} אחרת אם (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			اكسر;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		אם (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			اكسر;
		}
		handle_update_write(write_handle, len);
	}

	אם (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

ساكن فراغ
process_extended_home_directory(uint32_t id)
{
	حرف *username;
	بنية passwd *user_pw;
	صحيح r;
	Stat s;

	אם ((r = sshbuf_get_cstring(iqueue, &username, عدم)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	אם (username[0] == '\0') {
		user_pw = pw;
	} אחרת אם ((user_pw = getpwnam(username)) == عدم) {
		send_status(id, SSH2_FX_FAILURE);
		اذهب out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	حرر(username);
}

ساكن فراغ
process_extended_get_users_groups_by_id(uint32_t id)
{
	بنية passwd *user_pw;
	بنية group *gr;
	بنية sshbuf *uids, *gids, *usernames, *groupnames, *msg;
	صحيح r;
	u_int n, nusers = 0, ngroups = 0;
	ثابت حرف *name;

	אם ((usernames = sshbuf_new()) == عدم ||
	    (groupnames = sshbuf_new()) == عدم ||
	    (msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	כלעוד (sshbuf_len(uids) != 0) {
		אם ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == عدم ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		אם ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	כלעוד (sshbuf_len(gids) != 0) {
		אם ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == عدم ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		אם ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	אם ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_stringb(msg, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(msg, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(msg);
}

ساكن فراغ
process_extended(uint32_t id)
{
	حرف *request;
	صحيح r;
	ثابت بنية sftp_handler *exthand;

	אם ((r = sshbuf_get_cstring(iqueue, &request, عدم)) != 0)
		fatal_fr(r, "parse");
	אם ((exthand = extended_handler_byname(request)) == عدم) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} אחרת {
		אם (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		אחרת
			exthand->handler(id);
	}
	حرر(request);
}

/* stolen from ssh-agent */

ساكن فراغ
process(فراغ)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحيح i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	אם (buf_len < 5)
		החזר;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	אם (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	אם (buf_len < msg_len + 4)
		החזר;
	אם ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	אם ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	بدل (type) {
	حالة SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		اكسر;
	حالة SSH2_FXP_EXTENDED:
		אם (!init_done)
			fatal("Received extended request before init");
		אם ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		اكسر;
	افتراضي:
		אם (!init_done)
			fatal("Received %u request before init", type);
		אם ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		עבור (i = 0; handlers[i].handler != عدم; i++) {
			אם (type == handlers[i].type) {
				אם (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} אחרת {
					handlers[i].handler(id);
				}
				اكسر;
			}
		}
		אם (handlers[i].handler == عدم)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	אם (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	אם (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	אם (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
فراغ
sftp_server_cleanup_exit(صحيح i)
{
	אם (pw != عدم && client_addr != عدم) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ساكن فراغ
sftp_server_usage(فراغ)
{
	خارجي حرف *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

صحيح
sftp_server_main(صحيح argc, حرف **argv, بنية passwd *user_pw)
{
	صحيح i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	حرف *cp, *homedir = عدم, uidstr[32], buf[4*4096];
	long mask;

	خارجي حرف *optarg;
	خارجي حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	כלעוד (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		بدل (ch) {
		حالة 'Q':
			אם (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			עבור (i = 0; handlers[i].handler != عدم; i++)
				printf("%s\n", handlers[i].name);
			עבור (i = 0; extended_handlers[i].handler != عدم; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			اكسر;
		حالة 'R':
			readonly = 1;
			اكسر;
		حالة 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			اكسر;
		حالة 'e':
			log_stderr = 1;
			اكسر;
		حالة 'l':
			log_level = log_level_number(optarg);
			אם (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			اكسر;
		حالة 'f':
			log_facility = log_facility_number(optarg);
			אם (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			اكسر;
		حالة 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, حجم(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (حرف *)عدم);
			حرر(cp);
			اكسر;
		حالة 'p':
			אם (request_allowlist != عدم)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			اكسر;
		حالة 'P':
			אם (request_denylist != عدم)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			اكسر;
		حالة 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			אם (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(فراغ)umask((mode_t)mask);
			اكسر;
		حالة 'h':
		افتراضي:
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

	אם ((cp = getenv("SSH_CONNECTION")) != عدم) {
		client_addr = xstrdup(cp);
		אם ((cp = strchr(client_addr, ' ')) == عدم) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} אחרת
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	אם ((iqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((oqueue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	אם (homedir != عدم) {
		אם (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	עבור (;;) {
		بنية pollfd pfd[2];

		memset(pfd, 0, حجم pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		אם ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		אחרת אם (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		אם (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		אם (poll(pfd, 2, -1) == -1) {
			אם (errno == EINTR)
				استمر;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		אם (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = اقرأ(in, buf, حجم buf);
			אם (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} אחרת אם (len == -1) {
				אם (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} אחרת אם ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		אם (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = اكتب(out, sshbuf_ptr(oqueue), olen);
			אם (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} אחרת אם (len == -1) {
				sftp_server_cleanup_exit(1);
				אם (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} אחרת אם ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		אם (r == 0)
			process();
		אחרת אם (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
