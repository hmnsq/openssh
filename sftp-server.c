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

حرف *sftp_realpath(ثابت حرف *, حرف *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#تعریف_کرو SFTP_MAX_READ_لمبائی (SFTP_MAX_پیغام_لمبائی - 1024)

/* Our verbosity */
ساکن LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ساکن ساخت passwd *pw = تہی;
ساکن حرف *client_addr = تہی;

/* input and output queue */
ساخت sshbuf *iqueue;
ساخت sshbuf *oqueue;

/* Version of client */
ساکن u_int نسخہ;

/* SSH2_FXP_INIT received */
ساکن صحیح init_مکمل;

/* Disable writes */
ساکن صحیح readonly;

/* Requests that are allowed/denied */
ساکن حرف *request_allowlist, *request_denylist;

/* portable attributes, etc. */
قسمتعریف ساخت Stat Stat;

ساخت Stat {
	حرف *name;
	حرف *long_name;
	Attrib attrib;
};

/* Packet handlers */
ساکن خالی process_open(uint32_t id);
ساکن خالی process_close(uint32_t id);
ساکن خالی process_read(uint32_t id);
ساکن خالی process_write(uint32_t id);
ساکن خالی process_stat(uint32_t id);
ساکن خالی process_lstat(uint32_t id);
ساکن خالی process_fstat(uint32_t id);
ساکن خالی process_setstat(uint32_t id);
ساکن خالی process_fsetstat(uint32_t id);
ساکن خالی process_opendir(uint32_t id);
ساکن خالی process_readdir(uint32_t id);
ساکن خالی process_remove(uint32_t id);
ساکن خالی process_mkdir(uint32_t id);
ساکن خالی process_rmdir(uint32_t id);
ساکن خالی process_realpath(uint32_t id);
ساکن خالی process_rename(uint32_t id);
ساکن خالی process_readlink(uint32_t id);
ساکن خالی process_symlink(uint32_t id);
ساکن خالی process_extended_posix_rename(uint32_t id);
ساکن خالی process_extended_statvfs(uint32_t id);
ساکن خالی process_extended_fstatvfs(uint32_t id);
ساکن خالی process_extended_hardlink(uint32_t id);
ساکن خالی process_extended_fsync(uint32_t id);
ساکن خالی process_extended_lsetstat(uint32_t id);
ساکن خالی process_extended_limits(uint32_t id);
ساکن خالی process_extended_expand(uint32_t id);
ساکن خالی process_extended_copy_ڈیٹا(uint32_t id);
ساکن خالی process_extended_home_directory(uint32_t id);
ساکن خالی process_extended_get_users_groups_by_id(uint32_t id);
ساکن خالی process_extended(uint32_t id);

ساخت sftp_handler {
	ثابت حرف *name;	/* user-visible name for fine-grained perms */
	ثابت حرف *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	خالی (*handler)(uint32_t);
	صحیح does_write;		/* if nonzero, banned for readonly mode */
};

ساکن ثابت ساخت sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", تہی, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", تہی, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", تہی, SSH2_FXP_READ, process_read, 0 },
	{ "write", تہی, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", تہی, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", تہی, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", تہی, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", تہی, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", تہی, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", تہی, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", تہی, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", تہی, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", تہی, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", تہی, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", تہی, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", تہی, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", تہی, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", تہی, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ تہی, تہی, 0, تہی, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ساکن ثابت ساخت sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_ڈیٹا, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ تہی, تہی, 0, تہی, 0 }
};

ساکن ثابت ساخت sftp_handler *
extended_handler_byname(ثابت حرف *name)
{
	صحیح i;

	برائے (i = 0; extended_handlers[i].handler != تہی; i++) {
		اگر (strcmp(name, extended_handlers[i].ext_name) == 0)
			واپس &extended_handlers[i];
	}
	واپس تہی;
}

ساکن صحیح
request_permitted(ثابت ساخت sftp_handler *h)
{
	حرف *نتیجہ;

	اگر (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		واپس 0;
	}
	اگر (request_denylist != تہی &&
	    ((نتیجہ = مطابقت_list(h->name, request_denylist, تہی))) != تہی) {
		آزاد(نتیجہ);
		verbose("Refusing denylisted %s request", h->name);
		واپس 0;
	}
	اگر (request_allowlist != تہی &&
	    ((نتیجہ = مطابقت_list(h->name, request_allowlist, تہی))) != تہی) {
		آزاد(نتیجہ);
		debug2("Permitting allowlisted %s request", h->name);
		واپس 1;
	}
	اگر (request_allowlist != تہی) {
		verbose("Refusing non-allowlisted %s request", h->name);
		واپس 0;
	}
	واپس 1;
}

ساکن صحیح
errno_مقصد_portable(صحیح unixerrno)
{
	صحیح ret = 0;

	انتخاب (unixerrno) {
	حالت 0:
		ret = SSH2_FX_OK;
		توڑو;
	حالت ENOENT:
	حالت ENOTDIR:
	حالت EBADF:
	حالت ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		توڑو;
	حالت EPERM:
	حالت EACCES:
	حالت EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		توڑو;
	حالت ENAMETOOLONG:
	حالت EINVAL:
		ret = SSH2_FX_BAD_پیغام;
		توڑو;
	حالت ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		توڑو;
	طےشدہ:
		ret = SSH2_FX_FAILURE;
		توڑو;
	}
	واپس ret;
}

ساکن صحیح
flags_from_portable(صحیح pflags)
{
	صحیح flags = 0;

	اگر ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} ورنہ اگر (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} ورنہ اگر (pflags & SSH2_FXF_WRITE) {
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
	واپس flags;
}

ساکن ثابت حرف *
string_from_portable(صحیح pflags)
{
	ساکن حرف ret[128];

	*ret = '\0';

#تعریف_کرو PAPPEND(str)	{				\
		اگر (*ret != '\0')			\
			strlcat(ret, ",", حجم(ret));	\
		strlcat(ret, str, حجم(ret));		\
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

	واپس ret;
}

/* handle handles */

قسمتعریف ساخت Handle Handle;
ساخت Handle {
	صحیح use;
	DIR *dirp;
	صحیح fd;
	صحیح flags;
	حرف *name;
	uint64_t بائٹیں_read, بائٹیں_write;
	صحیح اگلا_غیر_مستعمل;
};

شمار {
	HANDLE_غیر_مستعمل,
	HANDLE_DIR,
	HANDLE_FILE
};

ساکن Handle *handles = تہی;
ساکن u_int عدد_handles = 0;
ساکن صحیح پہلا_غیر_مستعمل_handle = -1;

ساکن خالی handle_غیر_مستعمل(صحیح i)
{
	handles[i].use = HANDLE_غیر_مستعمل;
	handles[i].اگلا_غیر_مستعمل = پہلا_غیر_مستعمل_handle;
	پہلا_غیر_مستعمل_handle = i;
}

ساکن صحیح
handle_new(صحیح use, ثابت حرف *name, صحیح fd, صحیح flags, DIR *dirp)
{
	صحیح i;

	اگر (پہلا_غیر_مستعمل_handle == -1) {
		اگر (عدد_handles + 1 <= عدد_handles)
			واپس -1;
		عدد_handles++;
		handles = xreallocarray(handles, عدد_handles, حجم(Handle));
		handle_غیر_مستعمل(عدد_handles - 1);
	}

	i = پہلا_غیر_مستعمل_handle;
	پہلا_غیر_مستعمل_handle = handles[i].اگلا_غیر_مستعمل;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].بائٹیں_read = handles[i].بائٹیں_write = 0;

	واپس i;
}

ساکن صحیح
handle_is_ok(صحیح i, صحیح type)
{
	واپس i >= 0 && (u_int)i < عدد_handles && handles[i].use == type;
}

ساکن صحیح
handle_مقصد_string(صحیح handle, u_char **stringp, صحیح *hlenp)
{
	اگر (stringp == تہی || hlenp == تہی)
		واپس -1;
	*stringp = xmalloc(حجم(int32_t));
	put_u32(*stringp, handle);
	*hlenp = حجم(int32_t);
	واپس 0;
}

ساکن صحیح
handle_from_string(ثابت u_char *handle, u_int hlen)
{
	صحیح val;

	اگر (hlen != حجم(int32_t))
		واپس -1;
	val = get_u32(handle);
	اگر (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		واپس val;
	واپس -1;
}

ساکن حرف *
handle_مقصد_name(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		واپس handles[handle].name;
	واپس تہی;
}

ساکن DIR *
handle_مقصد_dir(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_DIR))
		واپس handles[handle].dirp;
	واپس تہی;
}

ساکن صحیح
handle_مقصد_fd(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		واپس handles[handle].fd;
	واپس -1;
}

ساکن صحیح
handle_مقصد_flags(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		واپس handles[handle].flags;
	واپس 0;
}

ساکن خالی
handle_update_read(صحیح handle, ssize_t بائٹیں)
{
	اگر (handle_is_ok(handle, HANDLE_FILE) && بائٹیں > 0)
		handles[handle].بائٹیں_read += بائٹیں;
}

ساکن خالی
handle_update_write(صحیح handle, ssize_t بائٹیں)
{
	اگر (handle_is_ok(handle, HANDLE_FILE) && بائٹیں > 0)
		handles[handle].بائٹیں_write += بائٹیں;
}

ساکن uint64_t
handle_بائٹیں_read(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		واپس (handles[handle].بائٹیں_read);
	واپس 0;
}

ساکن uint64_t
handle_بائٹیں_write(صحیح handle)
{
	اگر (handle_is_ok(handle, HANDLE_FILE))
		واپس (handles[handle].بائٹیں_write);
	واپس 0;
}

ساکن صحیح
handle_close(صحیح handle)
{
	صحیح ret = -1;

	اگر (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		آزاد(handles[handle].name);
		handle_غیر_مستعمل(handle);
	} ورنہ اگر (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		آزاد(handles[handle].name);
		handle_غیر_مستعمل(handle);
	} ورنہ {
		errno = ENOENT;
	}
	واپس ret;
}

ساکن خالی
handle_log_close(صحیح handle, حرف *emsg)
{
	اگر (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == تہی ? "" : emsg, emsg == تہی ? "" : " ",
		    handle_مقصد_name(handle),
		    (غیرعلامتی طویل طویل)handle_بائٹیں_read(handle),
		    (غیرعلامتی طویل طویل)handle_بائٹیں_write(handle));
	} ورنہ {
		logit("%s%sclosedir \"%s\"",
		    emsg == تہی ? "" : emsg, emsg == تہی ? "" : " ",
		    handle_مقصد_name(handle));
	}
}

ساکن خالی
handle_log_exit(خالی)
{
	u_int i;

	برائے (i = 0; i < عدد_handles; i++)
		اگر (handles[i].use != HANDLE_غیر_مستعمل)
			handle_log_close(i, "forced");
}

ساکن صحیح
get_handle(ساخت sshbuf *قطار, صحیح *hp)
{
	u_char *handle;
	صحیح r;
	سائز_t hlen;

	*hp = -1;
	اگر ((r = sshbuf_get_string(قطار, &handle, &hlen)) != 0)
		واپس r;
	اگر (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	آزاد(handle);
	واپس 0;
}

/* send replies */

ساکن خالی
send_پیغام(ساخت sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ساکن ثابت حرف *
حالت_مقصد_پیغام(uint32_t حالت_2)
{
	ساکن ثابت حرف * ثابت حالت_messages[] = {
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
	واپس (حالت_messages[MINIMUM(حالت_2,SSH2_FX_MAX)]);
}

ساکن خالی
send_حالت_errmsg(uint32_t id, uint32_t حالت_2, ثابت حرف *errmsg)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	debug3("request %u: sent status %u", id, حالت_2);
	اگر (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (حالت_2 != SSH2_FX_OK && حالت_2 != SSH2_FX_EOF))
		logit("sent status %s", حالت_مقصد_پیغام(حالت_2));
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_حالت)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, حالت_2)) != 0)
		fatal_fr(r, "compose");
	اگر (نسخہ >= 3) {
		اگر ((r = sshbuf_put_cstring(پیغام, errmsg == تہی ?
		    حالت_مقصد_پیغام(حالت_2) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
send_حالت(uint32_t id, uint32_t حالت_2)
{
	send_حالت_errmsg(id, حالت_2, تہی);
}

ساکن خالی
send_ڈیٹا_or_handle(حرف type, uint32_t id, ثابت u_char *ڈیٹا, صحیح dlen)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, type)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, ڈیٹا, dlen)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
send_ڈیٹا(uint32_t id, ثابت u_char *ڈیٹا, صحیح dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_ڈیٹا_or_handle(SSH2_FXP_ڈیٹا, id, ڈیٹا, dlen);
}

ساکن خالی
send_handle(uint32_t id, صحیح handle)
{
	u_char *string;
	صحیح hlen;

	handle_مقصد_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_ڈیٹا_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	آزاد(string);
}

ساکن خالی
send_نام(uint32_t id, صحیح گنتی, ثابت Stat *stats)
{
	ساخت sshbuf *پیغام;
	صحیح i, r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, گنتی)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, گنتی);
	برائے (i = 0; i < گنتی; i++) {
		اگر ((r = sshbuf_put_cstring(پیغام, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(پیغام, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
send_attrib(uint32_t id, ثابت Attrib *a)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
send_statvfs(uint32_t id, ساخت statvfs *st)
{
	ساخت sshbuf *پیغام;
	uint64_t flag;
	صحیح r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED_جواب)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_بلاکیں)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, FSID_مقصد_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(پیغام, flag)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ساکن صحیح
compose_extension(ساخت sshbuf *پیغام, ثابت حرف *name, ثابت حرف *ver)
{
	صحیح r;
	ثابت ساخت sftp_handler *exthnd;

	اگر ((exthnd = extended_handler_byname(name)) == تہی)
		fatal_f("internal error: no handler for %s", name);
	اگر (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		واپس 0;
	}
	اگر ((r = sshbuf_put_cstring(پیغام, name)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	واپس 0;
}

/* parse incoming */

ساکن خالی
process_init(خالی)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((r = sshbuf_get_u32(iqueue, &نسخہ)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", نسخہ);
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_نسخہ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, SSH2_FILEXFER_نسخہ)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(پیغام, "posix-rename@openssh.com", "1");
	compose_extension(پیغام, "statvfs@openssh.com", "2");
	compose_extension(پیغام, "fstatvfs@openssh.com", "2");
	compose_extension(پیغام, "hardlink@openssh.com", "1");
	compose_extension(پیغام, "fsync@openssh.com", "1");
	compose_extension(پیغام, "lsetstat@openssh.com", "1");
	compose_extension(پیغام, "limits@openssh.com", "1");
	compose_extension(پیغام, "expand-path@openssh.com", "1");
	compose_extension(پیغام, "copy-data", "1");
	compose_extension(پیغام, "home-directory", "1");
	compose_extension(پیغام, "users-groups-by-id@openssh.com", "1");

	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	حرف *name;
	صحیح r, handle, fd, flags, منوال, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	منوال = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), منوال);
	اگر (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		حالت_2 = SSH2_FX_PERMISSION_DENIED;
	} ورنہ {
		fd = open(name, flags, منوال);
		اگر (fd == -1) {
			حالت_2 = errno_مقصد_portable(errno);
		} ورنہ {
			handle = handle_new(HANDLE_FILE, name, fd, flags, تہی);
			اگر (handle < 0) {
				close(fd);
			} ورنہ {
				send_handle(id, handle);
				حالت_2 = SSH2_FX_OK;
			}
		}
	}
	اگر (حالت_2 != SSH2_FX_OK)
		send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_close(uint32_t id)
{
	صحیح r, handle, ret, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, تہی);
	ret = handle_close(handle);
	حالت_2 = (ret == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
}

ساکن خالی
process_read(uint32_t id)
{
	ساکن u_char *buf;
	ساکن سائز_t buflen;
	uint32_t len;
	صحیح r, handle, fd, ret, حالت_2 = SSH2_FX_FAILURE;
	uint64_t off;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_مقصد_name(handle), handle, (غیرعلامتی طویل طویل)off, len);
	اگر ((fd = handle_مقصد_fd(handle)) == -1)
		جاؤ برآمد;
	اگر (len > SFTP_MAX_READ_لمبائی) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_لمبائی);
		len = SFTP_MAX_READ_لمبائی;
	}
	اگر (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		اگر ((buf = realloc(buf, len)) == تہی)
			fatal_f("realloc failed");
		buflen = len;
	}
	اگر (lseek(fd, off, SEEK_SET) == -1) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("seek \"%.100s\": %s", handle_مقصد_name(handle),
		    strerror(errno));
		جاؤ برآمد;
	}
	اگر (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} ورنہ اگر ((ret = اقرأ(fd, buf, len)) == -1) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("read \"%.100s\": %s", handle_مقصد_name(handle),
		    strerror(errno));
		جاؤ برآمد;
	} ورنہ اگر (ret == 0) {
		حالت_2 = SSH2_FX_EOF;
		جاؤ برآمد;
	}
	send_ڈیٹا(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	حالت_2 = SSH2_FX_OK;
 برآمد:
	اگر (حالت_2 != SSH2_FX_OK)
		send_حالت(id, حالت_2);
}

ساکن خالی
process_write(uint32_t id)
{
	uint64_t off;
	سائز_t len;
	صحیح r, handle, fd, ret, حالت_2;
	u_char *ڈیٹا;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &ڈیٹا, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_مقصد_name(handle), handle, (غیرعلامتی طویل طویل)off, len);
	fd = handle_مقصد_fd(handle);

	اگر (fd < 0)
		حالت_2 = SSH2_FX_FAILURE;
	ورنہ {
		اگر (!(handle_مقصد_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			حالت_2 = errno_مقصد_portable(errno);
			error_f("seek \"%.100s\": %s", handle_مقصد_name(handle),
			    strerror(errno));
		} ورنہ {
/* XXX ATOMICIO ? */
			ret = اكتب(fd, ڈیٹا, len);
			اگر (ret == -1) {
				حالت_2 = errno_مقصد_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_مقصد_name(handle), strerror(errno));
			} ورنہ اگر ((سائز_t)ret == len) {
				حالت_2 = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} ورنہ {
				debug2_f("nothing at all written");
				حالت_2 = SSH2_FX_FAILURE;
			}
		}
	}
	send_حالت(id, حالت_2);
	آزاد(ڈیٹا);
}

ساکن خالی
process_do_stat(uint32_t id, صحیح do_lstat)
{
	Attrib a;
	ساخت stat st;
	حرف *name;
	صحیح r, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	اگر (r == -1) {
		حالت_2 = errno_مقصد_portable(errno);
	} ورنہ {
		stat_مقصد_attrib(&st, &a);
		send_attrib(id, &a);
		حالت_2 = SSH2_FX_OK;
	}
	اگر (حالت_2 != SSH2_FX_OK)
		send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ساکن خالی
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ساکن خالی
process_fstat(uint32_t id)
{
	Attrib a;
	ساخت stat st;
	صحیح fd, r, handle, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_مقصد_name(handle), handle);
	fd = handle_مقصد_fd(handle);
	اگر (fd >= 0) {
		r = fstat(fd, &st);
		اگر (r == -1) {
			حالت_2 = errno_مقصد_portable(errno);
		} ورنہ {
			stat_مقصد_attrib(&st, &a);
			send_attrib(id, &a);
			حالت_2 = SSH2_FX_OK;
		}
	}
	اگر (حالت_2 != SSH2_FX_OK)
		send_حالت(id, حالت_2);
}

ساکن ساخت timeval *
attrib_مقصد_tv(ثابت Attrib *a)
{
	ساکن ساخت timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	واپس tv;
}

ساکن ساخت timespec *
attrib_مقصد_ts(ثابت Attrib *a)
{
	ساکن ساخت timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	واپس ts;
}

ساکن خالی
process_setstat(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحیح r, حالت_2 = SSH2_FX_OK;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	اگر (a.flags & SSH2_FILEXFER_ATTR_سائز) {
		logit("set \"%s\" size %llu",
		    name, (غیرعلامتی طویل طویل)a.سائز);
		r = truncate(name, a.سائز);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		حرف buf[64];
		time_t t = a.mtime;

		strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_مقصد_tv(&a));
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_fsetstat(uint32_t id)
{
	Attrib a;
	صحیح handle, fd, r;
	صحیح حالت_2 = SSH2_FX_OK;

	اگر ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_مقصد_fd(handle);
	اگر (fd < 0)
		حالت_2 = SSH2_FX_FAILURE;
	ورنہ {
		حرف *name = handle_مقصد_name(handle);

		اگر (a.flags & SSH2_FILEXFER_ATTR_سائز) {
			logit("set \"%s\" size %llu",
			    name, (غیرعلامتی طویل طویل)a.سائز);
			r = ftruncate(fd, a.سائز);
			اگر (r == -1)
				حالت_2 = errno_مقصد_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#اگر_تعریف_شدہ HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#ورنہ
			r = chmod(name, a.perm & 07777);
#اگر_ختم
			اگر (r == -1)
				حالت_2 = errno_مقصد_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			حرف buf[64];
			time_t t = a.mtime;

			strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#اگر_تعریف_شدہ HAVE_FUTIMES
			r = futimes(fd, attrib_مقصد_tv(&a));
#ورنہ
			r = utimes(name, attrib_مقصد_tv(&a));
#اگر_ختم
			اگر (r == -1)
				حالت_2 = errno_مقصد_portable(errno);
		}
		اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#اگر_تعریف_شدہ HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#ورنہ
			r = chown(name, a.uid, a.gid);
#اگر_ختم
			اگر (r == -1)
				حالت_2 = errno_مقصد_portable(errno);
		}
	}
	send_حالت(id, حالت_2);
}

ساکن خالی
process_opendir(uint32_t id)
{
	DIR *dirp = تہی;
	حرف *راستہ;
	صحیح r, handle, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &راستہ, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", راستہ);
	dirp = opendir(راستہ);
	اگر (dirp == تہی) {
		حالت_2 = errno_مقصد_portable(errno);
	} ورنہ {
		handle = handle_new(HANDLE_DIR, راستہ, 0, 0, dirp);
		اگر (handle < 0) {
			closedir(dirp);
		} ورنہ {
			send_handle(id, handle);
			حالت_2 = SSH2_FX_OK;
		}

	}
	اگر (حالت_2 != SSH2_FX_OK)
		send_حالت(id, حالت_2);
	آزاد(راستہ);
}

ساکن خالی
process_readdir(uint32_t id)
{
	DIR *dirp;
	ساخت dirent *dp;
	حرف *راستہ;
	صحیح r, handle;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_مقصد_name(handle), handle);
	dirp = handle_مقصد_dir(handle);
	راستہ = handle_مقصد_name(handle);
	اگر (dirp == تہی || راستہ == تہی) {
		send_حالت(id, SSH2_FX_FAILURE);
	} ورنہ {
		ساخت stat st;
		حرف *pathname;
		Stat *stats;
		صحیح nstats = 10, گنتی = 0, i;

		stats = xcalloc(nstats, حجم(Stat));
		جب ((dp = readdir(dirp)) != تہی) {
			اگر (گنتی >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, حجم(Stat));
			}
			xasprintf(&pathname, "%s%s%s", راستہ,
			    strcmp(راستہ, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			آزاد(pathname);
			اگر (r == -1)
				جاری;
			stat_مقصد_attrib(&st, &(stats[گنتی].attrib));
			stats[گنتی].name = xstrdup(dp->d_name);
			stats[گنتی].long_name = ls_file(dp->d_name, &st,
			    0, 0, تہی, تہی);
			گنتی++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			اگر (گنتی == 100)
				توڑو;
		}
		اگر (گنتی > 0) {
			send_نام(id, گنتی, stats);
			برائے (i = 0; i < گنتی; i++) {
				آزاد(stats[i].name);
				آزاد(stats[i].long_name);
			}
		} ورنہ {
			send_حالت(id, SSH2_FX_EOF);
		}
		آزاد(stats);
	}
}

ساکن خالی
process_remove(uint32_t id)
{
	حرف *name;
	صحیح r, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_mkdir(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحیح r, منوال, حالت_2 = SSH2_FX_FAILURE;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	منوال = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, منوال);
	r = mkdir(name, منوال);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_rmdir(uint32_t id)
{
	حرف *name;
	صحیح r, حالت_2;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_realpath(uint32_t id)
{
	حرف resolvedname[PATH_MAX];
	حرف *راستہ;
	صحیح r;

	اگر ((r = sshbuf_get_cstring(iqueue, &راستہ, تہی)) != 0)
		fatal_fr(r, "parse");

	اگر (راستہ[0] == '\0') {
		آزاد(راستہ);
		راستہ = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", راستہ);
	اگر (sftp_realpath(راستہ, resolvedname) == تہی) {
		send_حالت(id, errno_مقصد_portable(errno));
	} ورنہ {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_نام(id, 1, &s);
	}
	آزاد(راستہ);
}

ساکن خالی
process_rename(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحیح r, حالت_2;
	ساخت stat sb;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	حالت_2 = SSH2_FX_FAILURE;
	اگر (lstat(oldpath, &sb) == -1)
		حالت_2 = errno_مقصد_portable(errno);
	ورنہ اگر (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		اگر (link(oldpath, newpath) == -1) {
			اگر (errno == EOPNOTSUPP || errno == ENOSYS
#اگر_تعریف_شدہ EXDEV
			    || errno == EXDEV
#اگر_ختم
#اگر_تعریف_شدہ LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#اگر_ختم
			    ) {
				ساخت stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				اگر (stat(newpath, &st) == -1) {
					اگر (rename(oldpath, newpath) == -1)
						حالت_2 =
						    errno_مقصد_portable(errno);
					ورنہ
						حالت_2 = SSH2_FX_OK;
				}
			} ورنہ {
				حالت_2 = errno_مقصد_portable(errno);
			}
		} ورنہ اگر (unlink(oldpath) == -1) {
			حالت_2 = errno_مقصد_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} ورنہ
			حالت_2 = SSH2_FX_OK;
	} ورنہ اگر (stat(newpath, &sb) == -1) {
		اگر (rename(oldpath, newpath) == -1)
			حالت_2 = errno_مقصد_portable(errno);
		ورنہ
			حالت_2 = SSH2_FX_OK;
	}
	send_حالت(id, حالت_2);
	آزاد(oldpath);
	آزاد(newpath);
}

ساکن خالی
process_readlink(uint32_t id)
{
	صحیح r, len;
	حرف buf[PATH_MAX];
	حرف *راستہ;

	اگر ((r = sshbuf_get_cstring(iqueue, &راستہ, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", راستہ);
	اگر ((len = readlink(راستہ, buf, حجم(buf) - 1)) == -1)
		send_حالت(id, errno_مقصد_portable(errno));
	ورنہ {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_نام(id, 1, &s);
	}
	آزاد(راستہ);
}

ساکن خالی
process_symlink(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحیح r, حالت_2;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(oldpath);
	آزاد(newpath);
}

ساکن خالی
process_extended_posix_rename(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحیح r, حالت_2;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(oldpath);
	آزاد(newpath);
}

ساکن خالی
process_extended_statvfs(uint32_t id)
{
	حرف *راستہ;
	ساخت statvfs st;
	صحیح r;

	اگر ((r = sshbuf_get_cstring(iqueue, &راستہ, تہی)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", راستہ);

	اگر (statvfs(راستہ, &st) != 0)
		send_حالت(id, errno_مقصد_portable(errno));
	ورنہ
		send_statvfs(id, &st);
	آزاد(راستہ);
}

ساکن خالی
process_extended_fstatvfs(uint32_t id)
{
	صحیح r, handle, fd;
	ساخت statvfs st;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_مقصد_name(handle), handle);
	اگر ((fd = handle_مقصد_fd(handle)) < 0) {
		send_حالت(id, SSH2_FX_FAILURE);
		واپس;
	}
	اگر (fstatvfs(fd, &st) != 0)
		send_حالت(id, errno_مقصد_portable(errno));
	ورنہ
		send_statvfs(id, &st);
}

ساکن خالی
process_extended_hardlink(uint32_t id)
{
	حرف *oldpath, *newpath;
	صحیح r, حالت_2;

	اگر ((r = sshbuf_get_cstring(iqueue, &oldpath, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	send_حالت(id, حالت_2);
	آزاد(oldpath);
	آزاد(newpath);
}

ساکن خالی
process_extended_fsync(uint32_t id)
{
	صحیح handle, fd, r, حالت_2 = SSH2_FX_OP_UNSUPPORTED;

	اگر ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_مقصد_name(handle));
	اگر ((fd = handle_مقصد_fd(handle)) < 0)
		حالت_2 = SSH2_FX_NO_SUCH_FILE;
	ورنہ اگر (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		حالت_2 = (r == -1) ? errno_مقصد_portable(errno) : SSH2_FX_OK;
	}
	send_حالت(id, حالت_2);
}

ساکن خالی
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	حرف *name;
	صحیح r, حالت_2 = SSH2_FX_OK;

	اگر ((r = sshbuf_get_cstring(iqueue, &name, تہی)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	اگر (a.flags & SSH2_FILEXFER_ATTR_سائز) {
		/* nonsensical for links */
		حالت_2 = SSH2_FX_BAD_پیغام;
		جاؤ برآمد;
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		حرف buf[64];
		time_t t = a.mtime;

		strftime(buf, حجم(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_مقصد_ts(&a), AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
	اگر (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		اگر (r == -1)
			حالت_2 = errno_مقصد_portable(errno);
	}
 برآمد:
	send_حالت(id, حالت_2);
	آزاد(name);
}

ساکن خالی
process_extended_limits(uint32_t id)
{
	ساخت sshbuf *پیغام;
	صحیح r;
	uint64_t nfiles = 0;
#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ساخت rlimit rlim;
#اگر_ختم

	debug("request %u: limits", id);

#اگر defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	اگر (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#اگر_ختم

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED_جواب)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(پیغام, SFTP_MAX_پیغام_لمبائی)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(پیغام, SFTP_MAX_READ_لمبائی)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(پیغام, SFTP_MAX_پیغام_لمبائی - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(پیغام, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(پیغام);
	sshbuf_free(پیغام);
}

ساکن خالی
process_extended_expand(uint32_t id)
{
	حرف cwd[PATH_MAX], resolvedname[PATH_MAX];
	حرف *راستہ, *npath;
	صحیح r;
	Stat s;

	اگر ((r = sshbuf_get_cstring(iqueue, &راستہ, تہی)) != 0)
		fatal_fr(r, "parse");
	اگر (getcwd(cwd, حجم(cwd)) == تہی) {
		send_حالت(id, errno_مقصد_portable(errno));
		جاؤ برآمد;
	}

	debug3("request %u: expand, original \"%s\"", id, راستہ);
	اگر (راستہ[0] == '\0') {
		/* empty path */
		آزاد(راستہ);
		راستہ = xstrdup(".");
	} ورنہ اگر (*راستہ == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		اگر (strcmp(راستہ, "~") == 0) {
			آزاد(راستہ);
			راستہ = xstrdup(cwd);
		} ورنہ اگر (لڑی_موازنہ(راستہ, "~/", 2) == 0) {
			npath = xstrdup(راستہ + 2);
			آزاد(راستہ);
			xasprintf(&راستہ, "%s/%s", cwd, npath);
			آزاد(npath);
		} ورنہ {
			/* ~user expansions */
			اگر (tilde_expand(راستہ, pw->pw_uid, &npath) != 0) {
				send_حالت_errmsg(id,
				    errno_مقصد_portable(ENOENT), "no such user");
				جاؤ برآمد;
			}
			آزاد(راستہ);
			راستہ = npath;
		}
	} ورنہ اگر (*راستہ != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, راستہ);
		آزاد(راستہ);
		راستہ = npath;
	}
	verbose("expand \"%s\"", راستہ);
	اگر (sftp_realpath(راستہ, resolvedname) == تہی) {
		send_حالت(id, errno_مقصد_portable(errno));
		جاؤ برآمد;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_نام(id, 1, &s);
 برآمد:
	آزاد(راستہ);
}

ساکن خالی
process_extended_copy_ڈیٹا(uint32_t id)
{
	u_char buf[64*1024];
	صحیح read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	صحیح r, copy_until_eof, حالت_2 = SSH2_FX_OP_UNSUPPORTED;
	سائز_t ret;
	ساخت stat st_read, st_write;

	اگر ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_مقصد_name(read_handle), read_handle,
	    (غیرعلامتی طویل طویل)read_off, (غیرعلامتی طویل طویل)read_len,
	    handle_مقصد_name(write_handle), write_handle,
	    (غیرعلامتی طویل طویل)write_off);

	/* For read length of 0, we read until EOF. */
	اگر (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} ورنہ
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_مقصد_fd(read_handle);
	write_fd = handle_مقصد_fd(write_handle);
	اگر (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		حالت_2 = errno_مقصد_portable(EBADF);
		جاؤ برآمد;
	}
	اگر (fstat(read_fd, &st_read) != 0) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		جاؤ برآمد;
	}
	اگر (fstat(write_fd, &st_write) != 0) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		جاؤ برآمد;
	}
	اگر (read_handle == write_handle ||
	    !strcmp(handle_مقصد_name(read_handle), handle_مقصد_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_مقصد_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_مقصد_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		حالت_2 = SSH2_FX_FAILURE;
		جاؤ برآمد;
	}

	اگر (lseek(read_fd, read_off, SEEK_SET) < 0) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("read_seek failed");
		جاؤ برآمد;
	}

	اگر ((handle_مقصد_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		حالت_2 = errno_مقصد_portable(errno);
		error_f("write_seek failed");
		جاؤ برآمد;
	}

	/* Process the request in chunks. */
	جب (read_len > 0 || copy_until_eof) {
		len = MINIMUM(حجم(buf), read_len);
		read_len -= len;

		ret = atomicio(اقرأ, read_fd, buf, len);
		اگر (ret == 0 && errno == EPIPE) {
			حالت_2 = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			توڑو;
		} ورنہ اگر (ret == 0) {
			حالت_2 = errno_مقصد_portable(errno);
			error_f("read failed: %s", strerror(errno));
			توڑو;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		اگر (ret != len) {
			حالت_2 = errno_مقصد_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (غیرعلامتی طویل طویل)ret, (غیرعلامتی طویل طویل)len,
			    strerror(errno));
			توڑو;
		}
		handle_update_write(write_handle, len);
	}

	اگر (read_len == 0)
		حالت_2 = SSH2_FX_OK;

 برآمد:
	send_حالت(id, حالت_2);
}

ساکن خالی
process_extended_home_directory(uint32_t id)
{
	حرف *username;
	ساخت passwd *user_pw;
	صحیح r;
	Stat s;

	اگر ((r = sshbuf_get_cstring(iqueue, &username, تہی)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	اگر (username[0] == '\0') {
		user_pw = pw;
	} ورنہ اگر ((user_pw = getpwnam(username)) == تہی) {
		send_حالت(id, SSH2_FX_FAILURE);
		جاؤ برآمد;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_نام(id, 1, &s);
 برآمد:
	آزاد(username);
}

ساکن خالی
process_extended_get_users_groups_by_id(uint32_t id)
{
	ساخت passwd *user_pw;
	ساخت گروہ *gr;
	ساخت sshbuf *uids, *gids, *usernames, *groupnames, *پیغام;
	صحیح r;
	u_int n, nusers = 0, ngroups = 0;
	ثابت حرف *name;

	اگر ((usernames = sshbuf_new()) == تہی ||
	    (groupnames = sshbuf_new()) == تہی ||
	    (پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	جب (sshbuf_len(uids) != 0) {
		اگر ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == تہی ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		اگر ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	جب (sshbuf_len(gids) != 0) {
		اگر ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == تہی ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		اگر ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED_جواب)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(پیغام);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(پیغام);
}

ساکن خالی
process_extended(uint32_t id)
{
	حرف *request;
	صحیح r;
	ثابت ساخت sftp_handler *exthand;

	اگر ((r = sshbuf_get_cstring(iqueue, &request, تہی)) != 0)
		fatal_fr(r, "parse");
	اگر ((exthand = extended_handler_byname(request)) == تہی) {
		error("Unknown extended request \"%.100s\"", request);
		send_حالت(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} ورنہ {
		اگر (!request_permitted(exthand))
			send_حالت(id, SSH2_FX_PERMISSION_DENIED);
		ورنہ
			exthand->handler(id);
	}
	آزاد(request);
}

/* stolen from ssh-agent */

ساکن خالی
process(خالی)
{
	u_int پیغام_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ثابت u_char *cp;
	صحیح i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	اگر (buf_len < 5)
		واپس;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	پیغام_len = get_u32(cp);
	اگر (پیغام_len > SFTP_MAX_پیغام_لمبائی) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	اگر (buf_len < پیغام_len + 4)
		واپس;
	اگر ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	اگر ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	انتخاب (type) {
	حالت SSH2_FXP_INIT:
		process_init();
		init_مکمل = 1;
		توڑو;
	حالت SSH2_FXP_EXTENDED:
		اگر (!init_مکمل)
			fatal("Received extended request before init");
		اگر ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		توڑو;
	طےشدہ:
		اگر (!init_مکمل)
			fatal("Received %u request before init", type);
		اگر ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		برائے (i = 0; handlers[i].handler != تہی; i++) {
			اگر (type == handlers[i].type) {
				اگر (!request_permitted(&handlers[i])) {
					send_حالت(id,
					    SSH2_FX_PERMISSION_DENIED);
				} ورنہ {
					handlers[i].handler(id);
				}
				توڑو;
			}
		}
		اگر (handlers[i].handler == تہی)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	اگر (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	اگر (پیغام_len < consumed) {
		error("msg_len %u < consumed %u", پیغام_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	اگر (پیغام_len > consumed &&
	    (r = sshbuf_consume(iqueue, پیغام_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
خالی
sftp_server_cleanup_exit(صحیح i)
{
	اگر (pw != تہی && client_addr != تہی) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ساکن خالی
sftp_server_usage(خالی)
{
	خارجی حرف *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	باہر_نکلو(1);
}

صحیح
sftp_server_main(صحیح argc, حرف **argv, ساخت passwd *user_pw)
{
	صحیح i, r, اندر, برآمد, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	حرف *cp, *homedir = تہی, uidstr[32], buf[4*4096];
	طویل نقاب;

	خارجی حرف *optarg;
	خارجی حرف *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	جب (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		انتخاب (ch) {
		حالت 'Q':
			اگر (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				باہر_نکلو(1);
			}
			برائے (i = 0; handlers[i].handler != تہی; i++)
				لکھو("%s\n", handlers[i].name);
			برائے (i = 0; extended_handlers[i].handler != تہی; i++)
				لکھو("%s\n", extended_handlers[i].name);
			باہر_نکلو(0);
			توڑو;
		حالت 'R':
			readonly = 1;
			توڑو;
		حالت 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			توڑو;
		حالت 'e':
			log_stderr = 1;
			توڑو;
		حالت 'l':
			log_level = log_level_نمبر(optarg);
			اگر (log_level == SYSLOG_LEVEL_NOT_سیٹ)
				error("Invalid log level \"%s\"", optarg);
			توڑو;
		حالت 'f':
			log_facility = log_facility_نمبر(optarg);
			اگر (log_facility == SYSLOG_FACILITY_NOT_سیٹ)
				error("Invalid log facility \"%s\"", optarg);
			توڑو;
		حالت 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, حجم(uidstr), "%llu",
			    (غیرعلامتی طویل طویل)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (حرف *)تہی);
			آزاد(cp);
			توڑو;
		حالت 'p':
			اگر (request_allowlist != تہی)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			توڑو;
		حالت 'P':
			اگر (request_denylist != تہی)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			توڑو;
		حالت 'u':
			errno = 0;
			نقاب = strtol(optarg, &cp, 8);
			اگر (نقاب < 0 || نقاب > 0777 || *cp != '\0' ||
			    cp == optarg || (نقاب == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(خالی)umask((منوال_t)نقاب);
			توڑو;
		حالت 'h':
		طےشدہ:
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

	اگر ((cp = getenv("SSH_CONNECTION")) != تہی) {
		client_addr = xstrdup(cp);
		اگر ((cp = strchr(client_addr, ' ')) == تہی) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} ورنہ
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	اندر = STDIN_FILENO;
	برآمد = STDOUT_FILENO;

#اگر_تعریف_شدہ HAVE_CYGWIN
	setmode(اندر, O_ثنائی);
	setmode(برآمد, O_ثنائی);
#اگر_ختم

	اگر ((iqueue = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((oqueue = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	اگر (homedir != تہی) {
		اگر (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	برائے (;;) {
		ساخت pollfd pfd[2];

		memset(pfd, 0, حجم pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		اگر ((r = sshbuf_check_reserve(iqueue, حجم(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_پیغام_لمبائی)) == 0) {
			pfd[0].fd = اندر;
			pfd[0].events = POLLIN;
		}
		ورنہ اگر (r != SSH_ERR_NO_بفر_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		اگر (olen > 0) {
			pfd[1].fd = برآمد;
			pfd[1].events = POLLOUT;
		}

		اگر (poll(pfd, 2, -1) == -1) {
			اگر (errno == EINTR)
				جاری;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		اگر (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = اقرأ(اندر, buf, حجم buf);
			اگر (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} ورنہ اگر (len == -1) {
				اگر (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ورنہ اگر ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		اگر (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = اكتب(برآمد, sshbuf_ptr(oqueue), olen);
			اگر (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} ورنہ اگر (len == -1) {
				sftp_server_cleanup_exit(1);
				اگر (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ورنہ اگر ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_پیغام_لمبائی);
		اگر (r == 0)
			process();
		ورنہ اگر (r != SSH_ERR_NO_بفر_SPACE)
			fatal_fr(r, "reserve");
	}
}
