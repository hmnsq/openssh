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

#include "includes.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "match.h"
#include "uidswap.h"

#include "sftp.h"
#include "sftp-common.h"

var_na *sftp_realpath(const var_na *, var_na *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_MSG_LENGTH - 1024)

/* Our verbosity */
static LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
static sa_nracanaa passwd *pw = NULL;
static var_na *client_addr = NULL;

/* input and output queue */
sa_nracanaa sshbuf *iqueue;
sa_nracanaa sshbuf *oqueue;

/* Version of client */
static u_int version;

/* SSH2_FXP_INIT received */
static ཧྲིལ init_done;

/* Disable writes */
static ཧྲིལ readonly;

/* Requests that are allowed/denied */
static var_na *request_allowlist, *request_denylist;

/* portable attributes, etc. */
typedef sa_nracanaa Stat Stat;

sa_nracanaa Stat {
	var_na *name;
	var_na *long_name;
	Attrib attrib;
};

/* Packet handlers */
static void process_open(uint32_t id);
static void process_close(uint32_t id);
static void process_read(uint32_t id);
static void process_write(uint32_t id);
static void process_stat(uint32_t id);
static void process_lstat(uint32_t id);
static void process_fstat(uint32_t id);
static void process_setstat(uint32_t id);
static void process_fsetstat(uint32_t id);
static void process_opendir(uint32_t id);
static void process_readdir(uint32_t id);
static void process_remove(uint32_t id);
static void process_mkdir(uint32_t id);
static void process_rmdir(uint32_t id);
static void process_realpath(uint32_t id);
static void process_rename(uint32_t id);
static void process_readlink(uint32_t id);
static void process_symlink(uint32_t id);
static void process_extended_posix_rename(uint32_t id);
static void process_extended_statvfs(uint32_t id);
static void process_extended_fstatvfs(uint32_t id);
static void process_extended_hardlink(uint32_t id);
static void process_extended_fsync(uint32_t id);
static void process_extended_lsetstat(uint32_t id);
static void process_extended_limits(uint32_t id);
static void process_extended_expand(uint32_t id);
static void process_extended_copy_data(uint32_t id);
static void process_extended_home_directory(uint32_t id);
static void process_extended_get_users_groups_by_id(uint32_t id);
static void process_extended(uint32_t id);

sa_nracanaa sftp_handler {
	const var_na *name;	/* user-visible name for fine-grained perms */
	const var_na *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	void (*handler)(uint32_t);
	ཧྲིལ does_write;		/* if nonzero, banned for readonly mode */
};

static const sa_nracanaa sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", NULL, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", NULL, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", NULL, SSH2_FXP_READ, process_read, 0 },
	{ "write", NULL, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", NULL, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", NULL, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", NULL, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", NULL, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", NULL, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", NULL, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", NULL, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", NULL, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", NULL, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", NULL, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", NULL, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", NULL, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", NULL, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", NULL, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ NULL, NULL, 0, NULL, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
static const sa_nracanaa sftp_handler extended_handlers[] = {
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
	{ NULL, NULL, 0, NULL, 0 }
};

static const sa_nracanaa sftp_handler *
extended_handler_byname(const var_na *name)
{
	ཧྲིལ i;

	ཆེད་དུ (i = 0; extended_handlers[i].handler != NULL; i++) {
		གལ་ཏེ (strcmp(name, extended_handlers[i].ext_name) == 0)
			ཕྱིར &extended_handlers[i];
	}
	ཕྱིར NULL;
}

static ཧྲིལ
request_permitted(const sa_nracanaa sftp_handler *h)
{
	var_na *result;

	གལ་ཏེ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		ཕྱིར 0;
	}
	གལ་ཏེ (request_denylist != NULL &&
	    ((result = match_list(h->name, request_denylist, NULL))) != NULL) {
		free(result);
		verbose("Refusing denylisted %s request", h->name);
		ཕྱིར 0;
	}
	གལ་ཏེ (request_allowlist != NULL &&
	    ((result = match_list(h->name, request_allowlist, NULL))) != NULL) {
		free(result);
		debug2("Permitting allowlisted %s request", h->name);
		ཕྱིར 1;
	}
	གལ་ཏེ (request_allowlist != NULL) {
		verbose("Refusing non-allowlisted %s request", h->name);
		ཕྱིར 0;
	}
	ཕྱིར 1;
}

static ཧྲིལ
errno_to_portable(ཧྲིལ unixerrno)
{
	ཧྲིལ ret = 0;

	switch (unixerrno) {
	pak_sa 0:
		ret = SSH2_FX_OK;
		bha_nga;
	pak_sa ENOENT:
	pak_sa ENOTDIR:
	pak_sa EBADF:
	pak_sa ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		bha_nga;
	pak_sa EPERM:
	pak_sa EACCES:
	pak_sa EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		bha_nga;
	pak_sa ENAMETOOLONG:
	pak_sa EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		bha_nga;
	pak_sa ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		bha_nga;
	default:
		ret = SSH2_FX_FAILURE;
		bha_nga;
	}
	ཕྱིར ret;
}

static ཧྲིལ
flags_from_portable(ཧྲིལ pflags)
{
	ཧྲིལ flags = 0;

	གལ་ཏེ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} དེ་མིན གལ་ཏེ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} དེ་མིན གལ་ཏེ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	གལ་ཏེ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	གལ་ཏེ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	གལ་ཏེ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	གལ་ཏེ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	ཕྱིར flags;
}

static const var_na *
string_from_portable(ཧྲིལ pflags)
{
	static var_na ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		གལ་ཏེ (*ret != '\0')			\
			strlcat(ret, ",", parimaa_na(ret));	\
		strlcat(ret, str, parimaa_na(ret));		\
	}

	གལ་ཏེ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	གལ་ཏེ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	གལ་ཏེ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	གལ་ཏེ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	གལ་ཏེ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	གལ་ཏེ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	ཕྱིར ret;
}

/* handle handles */

typedef sa_nracanaa Handle Handle;
sa_nracanaa Handle {
	ཧྲིལ use;
	DIR *dirp;
	ཧྲིལ fd;
	ཧྲིལ flags;
	var_na *name;
	uint64_t bytes_read, bytes_write;
	ཧྲིལ next_unused;
};

ga_nanaa {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

static Handle *handles = NULL;
static u_int num_handles = 0;
static ཧྲིལ first_unused_handle = -1;

static void handle_unused(ཧྲིལ i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static ཧྲིལ
handle_new(ཧྲིལ use, const var_na *name, ཧྲིལ fd, ཧྲིལ flags, DIR *dirp)
{
	ཧྲིལ i;

	གལ་ཏེ (first_unused_handle == -1) {
		གལ་ཏེ (num_handles + 1 <= num_handles)
			ཕྱིར -1;
		num_handles++;
		handles = xreallocarray(handles, num_handles, parimaa_na(Handle));
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

	ཕྱིར i;
}

static ཧྲིལ
handle_is_ok(ཧྲིལ i, ཧྲིལ type)
{
	ཕྱིར i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

static ཧྲིལ
handle_to_string(ཧྲིལ handle, u_char **stringp, ཧྲིལ *hlenp)
{
	གལ་ཏེ (stringp == NULL || hlenp == NULL)
		ཕྱིར -1;
	*stringp = xmalloc(parimaa_na(int32_t));
	put_u32(*stringp, handle);
	*hlenp = parimaa_na(int32_t);
	ཕྱིར 0;
}

static ཧྲིལ
handle_from_string(const u_char *handle, u_int hlen)
{
	ཧྲིལ val;

	གལ་ཏེ (hlen != parimaa_na(int32_t))
		ཕྱིར -1;
	val = get_u32(handle);
	གལ་ཏེ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		ཕྱིར val;
	ཕྱིར -1;
}

static var_na *
handle_to_name(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		ཕྱིར handles[handle].name;
	ཕྱིར NULL;
}

static DIR *
handle_to_dir(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_DIR))
		ཕྱིར handles[handle].dirp;
	ཕྱིར NULL;
}

static ཧྲིལ
handle_to_fd(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE))
		ཕྱིར handles[handle].fd;
	ཕྱིར -1;
}

static ཧྲིལ
handle_to_flags(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE))
		ཕྱིར handles[handle].flags;
	ཕྱིར 0;
}

static void
handle_update_read(ཧྲིལ handle, ssize_t bytes)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

static void
handle_update_write(ཧྲིལ handle, ssize_t bytes)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

static uint64_t
handle_bytes_read(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE))
		ཕྱིར (handles[handle].bytes_read);
	ཕྱིར 0;
}

static uint64_t
handle_bytes_write(ཧྲིལ handle)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE))
		ཕྱིར (handles[handle].bytes_write);
	ཕྱིར 0;
}

static ཧྲིལ
handle_close(ཧྲིལ handle)
{
	ཧྲིལ ret = -1;

	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		free(handles[handle].name);
		handle_unused(handle);
	} དེ་མིན གལ་ཏེ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		free(handles[handle].name);
		handle_unused(handle);
	} དེ་མིན {
		errno = ENOENT;
	}
	ཕྱིར ret;
}

static void
handle_log_close(ཧྲིལ handle, var_na *emsg)
{
	གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} དེ་མིན {
		logit("%s%sclosedir \"%s\"",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle));
	}
}

static void
handle_log_exit(void)
{
	u_int i;

	ཆེད་དུ (i = 0; i < num_handles; i++)
		གལ་ཏེ (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

static ཧྲིལ
get_handle(sa_nracanaa sshbuf *queue, ཧྲིལ *hp)
{
	u_char *handle;
	ཧྲིལ r;
	size_t hlen;

	*hp = -1;
	གལ་ཏེ ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		ཕྱིར r;
	གལ་ཏེ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	free(handle);
	ཕྱིར 0;
}

/* send replies */

static void
send_msg(sa_nracanaa sshbuf *m)
{
	ཧྲིལ r;

	གལ་ཏེ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

static const var_na *
status_to_message(uint32_t status)
{
	static const var_na * const status_messages[] = {
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
	ཕྱིར (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

static void
send_status_errmsg(uint32_t id, uint32_t status, const var_na *errmsg)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ r;

	debug3("request %u: sent status %u", id, status);
	གལ་ཏེ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal_fr(r, "compose");
	གལ་ཏེ (version >= 3) {
		གལ་ཏེ ((r = sshbuf_put_cstring(msg, errmsg == NULL ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, NULL);
}

static void
send_data_or_handle(var_na type, uint32_t id, const u_char *data, ཧྲིལ dlen)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ r;

	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_data(uint32_t id, const u_char *data, ཧྲིལ dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(uint32_t id, ཧྲིལ handle)
{
	u_char *string;
	ཧྲིལ hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	free(string);
}

static void
send_names(uint32_t id, ཧྲིལ count, const Stat *stats)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ i, r;

	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, count);
	ཆེད་དུ (i = 0; i < count; i++) {
		གལ་ཏེ ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(msg, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(msg, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_attrib(uint32_t id, const Attrib *a)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_statvfs(uint32_t id, sa_nracanaa statvfs *st)
{
	sa_nracanaa sshbuf *msg;
	uint64_t flag;
	ཧྲིལ r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
static ཧྲིལ
compose_extension(sa_nracanaa sshbuf *msg, const var_na *name, const var_na *ver)
{
	ཧྲིལ r;
	const sa_nracanaa sftp_handler *exthnd;

	གལ་ཏེ ((exthnd = extended_handler_byname(name)) == NULL)
		fatal_f("internal error: no handler for %s", name);
	གལ་ཏེ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		ཕྱིར 0;
	}
	གལ་ཏེ ((r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	ཕྱིར 0;
}

/* parse incoming */

static void
process_init(void)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ r;

	གལ་ཏེ ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
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

static void
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	var_na *name;
	ཧྲིལ r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	གལ་ཏེ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} དེ་མིན {
		fd = open(name, flags, mode);
		གལ་ཏེ (fd == -1) {
			status = errno_to_portable(errno);
		} དེ་མིན {
			handle = handle_new(HANDLE_FILE, name, fd, flags, NULL);
			གལ་ཏེ (handle < 0) {
				close(fd);
			} དེ་མིན {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	གལ་ཏེ (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_close(uint32_t id)
{
	ཧྲིལ r, handle, ret, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, NULL);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

static void
process_read(uint32_t id)
{
	static u_char *buf;
	static size_t buflen;
	uint32_t len;
	ཧྲིལ r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	གལ་ཏེ ((fd = handle_to_fd(handle)) == -1)
		goto out;
	གལ་ཏེ (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	གལ་ཏེ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		གལ་ཏེ ((buf = realloc(buf, len)) == NULL)
			fatal_f("realloc failed");
		buflen = len;
	}
	གལ་ཏེ (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	}
	གལ་ཏེ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} དེ་མིན གལ་ཏེ ((ret = read(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	} དེ་མིན གལ་ཏེ (ret == 0) {
		status = SSH2_FX_EOF;
		goto out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	གལ་ཏེ (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	ཧྲིལ r, handle, fd, ret, status;
	u_char *data;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	གལ་ཏེ (fd < 0)
		status = SSH2_FX_FAILURE;
	དེ་མིན {
		གལ་ཏེ (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} དེ་མིན {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			གལ་ཏེ (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} དེ་མིན གལ་ཏེ ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} དེ་མིན {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	free(data);
}

static void
process_do_stat(uint32_t id, ཧྲིལ do_lstat)
{
	Attrib a;
	sa_nracanaa stat st;
	var_na *name;
	ཧྲིལ r, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	གལ་ཏེ (r == -1) {
		status = errno_to_portable(errno);
	} དེ་མིན {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	གལ་ཏེ (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

static void
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

static void
process_fstat(uint32_t id)
{
	Attrib a;
	sa_nracanaa stat st;
	ཧྲིལ fd, r, handle, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	གལ་ཏེ (fd >= 0) {
		r = fstat(fd, &st);
		གལ་ཏེ (r == -1) {
			status = errno_to_portable(errno);
		} དེ་མིན {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	གལ་ཏེ (status != SSH2_FX_OK)
		send_status(id, status);
}

static sa_nracanaa timeval *
attrib_to_tv(const Attrib *a)
{
	static sa_nracanaa timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	ཕྱིར tv;
}

static sa_nracanaa timespec *
attrib_to_ts(const Attrib *a)
{
	static sa_nracanaa timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	ཕྱིར ts;
}

static void
process_setstat(uint32_t id)
{
	Attrib a;
	var_na *name;
	ཧྲིལ r, status = SSH2_FX_OK;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		var_na buf[64];
		time_t t = a.mtime;

		strftime(buf, parimaa_na(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	free(name);
}

static void
process_fsetstat(uint32_t id)
{
	Attrib a;
	ཧྲིལ handle, fd, r;
	ཧྲིལ status = SSH2_FX_OK;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	གལ་ཏེ (fd < 0)
		status = SSH2_FX_FAILURE;
	དེ་མིན {
		var_na *name = handle_to_name(handle);

		གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			གལ་ཏེ (r == -1)
				status = errno_to_portable(errno);
		}
		གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#དེ་མིན
			r = chmod(name, a.perm & 07777);
#endif
			གལ་ཏེ (r == -1)
				status = errno_to_portable(errno);
		}
		གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			var_na buf[64];
			time_t t = a.mtime;

			strftime(buf, parimaa_na(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#དེ་མིན
			r = utimes(name, attrib_to_tv(&a));
#endif
			གལ་ཏེ (r == -1)
				status = errno_to_portable(errno);
		}
		གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#དེ་མིན
			r = chown(name, a.uid, a.gid);
#endif
			གལ་ཏེ (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

static void
process_opendir(uint32_t id)
{
	DIR *dirp = NULL;
	var_na *path;
	ཧྲིལ r, handle, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	གལ་ཏེ (dirp == NULL) {
		status = errno_to_portable(errno);
	} དེ་མིན {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		གལ་ཏེ (handle < 0) {
			closedir(dirp);
		} དེ་མིན {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	གལ་ཏེ (status != SSH2_FX_OK)
		send_status(id, status);
	free(path);
}

static void
process_readdir(uint32_t id)
{
	DIR *dirp;
	sa_nracanaa dirent *dp;
	var_na *path;
	ཧྲིལ r, handle;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	གལ་ཏེ (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} དེ་མིན {
		sa_nracanaa stat st;
		var_na *pathname;
		Stat *stats;
		ཧྲིལ nstats = 10, count = 0, i;

		stats = xcalloc(nstats, parimaa_na(Stat));
		སྐབས ((dp = readdir(dirp)) != NULL) {
			གལ་ཏེ (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, parimaa_na(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			free(pathname);
			གལ་ཏེ (r == -1)
				continue;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st,
			    0, 0, NULL, NULL);
			count++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			གལ་ཏེ (count == 100)
				bha_nga;
		}
		གལ་ཏེ (count > 0) {
			send_names(id, count, stats);
			ཆེད་དུ (i = 0; i < count; i++) {
				free(stats[i].name);
				free(stats[i].long_name);
			}
		} དེ་མིན {
			send_status(id, SSH2_FX_EOF);
		}
		free(stats);
	}
}

static void
process_remove(uint32_t id)
{
	var_na *name;
	ཧྲིལ r, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_mkdir(uint32_t id)
{
	Attrib a;
	var_na *name;
	ཧྲིལ r, mode, status = SSH2_FX_FAILURE;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_rmdir(uint32_t id)
{
	var_na *name;
	ཧྲིལ r, status;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_realpath(uint32_t id)
{
	var_na resolvedname[PATH_MAX];
	var_na *path;
	ཧྲིལ r;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	གལ་ཏེ (path[0] == '\0') {
		free(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	གལ་ཏེ (sftp_realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} དེ་མིན {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	free(path);
}

static void
process_rename(uint32_t id)
{
	var_na *oldpath, *newpath;
	ཧྲིལ r, status;
	sa_nracanaa stat sb;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	གལ་ཏེ (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	དེ་མིན གལ་ཏེ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		གལ་ཏེ (link(oldpath, newpath) == -1) {
			གལ་ཏེ (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				sa_nracanaa stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				གལ་ཏེ (stat(newpath, &st) == -1) {
					གལ་ཏེ (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					དེ་མིན
						status = SSH2_FX_OK;
				}
			} དེ་མིན {
				status = errno_to_portable(errno);
			}
		} དེ་མིན གལ་ཏེ (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} དེ་མིན
			status = SSH2_FX_OK;
	} དེ་མིན གལ་ཏེ (stat(newpath, &sb) == -1) {
		གལ་ཏེ (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		དེ་མིན
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_readlink(uint32_t id)
{
	ཧྲིལ r, len;
	var_na buf[PATH_MAX];
	var_na *path;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	གལ་ཏེ ((len = readlink(path, buf, parimaa_na(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	དེ་མིན {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	free(path);
}

static void
process_symlink(uint32_t id)
{
	var_na *oldpath, *newpath;
	ཧྲིལ r, status;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_posix_rename(uint32_t id)
{
	var_na *oldpath, *newpath;
	ཧྲིལ r, status;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_statvfs(uint32_t id)
{
	var_na *path;
	sa_nracanaa statvfs st;
	ཧྲིལ r;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	གལ་ཏེ (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	དེ་མིན
		send_statvfs(id, &st);
	free(path);
}

static void
process_extended_fstatvfs(uint32_t id)
{
	ཧྲིལ r, handle, fd;
	sa_nracanaa statvfs st;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	གལ་ཏེ ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		ཕྱིར;
	}
	གལ་ཏེ (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	དེ་མིན
		send_statvfs(id, &st);
}

static void
process_extended_hardlink(uint32_t id)
{
	var_na *oldpath, *newpath;
	ཧྲིལ r, status;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_fsync(uint32_t id)
{
	ཧྲིལ handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	གལ་ཏེ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	གལ་ཏེ ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	དེ་མིན གལ་ཏེ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

static void
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	var_na *name;
	ཧྲིལ r, status = SSH2_FX_OK;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		goto out;
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		var_na buf[64];
		time_t t = a.mtime;

		strftime(buf, parimaa_na(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
	གལ་ཏེ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		གལ་ཏེ (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	free(name);
}

static void
process_extended_limits(uint32_t id)
{
	sa_nracanaa sshbuf *msg;
	ཧྲིལ r;
	uint64_t nfiles = 0;
#གལ་ཏེ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	sa_nracanaa rlimit rlim;
#endif

	debug("request %u: limits", id);

#གལ་ཏེ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	གལ་ཏེ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	གལ་ཏེ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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

static void
process_extended_expand(uint32_t id)
{
	var_na cwd[PATH_MAX], resolvedname[PATH_MAX];
	var_na *path, *npath;
	ཧྲིལ r;
	Stat s;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	གལ་ཏེ (getcwd(cwd, parimaa_na(cwd)) == NULL) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	གལ་ཏེ (path[0] == '\0') {
		/* empty path */
		free(path);
		path = xstrdup(".");
	} དེ་མིན གལ་ཏེ (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		གལ་ཏེ (strcmp(path, "~") == 0) {
			free(path);
			path = xstrdup(cwd);
		} དེ་མིན གལ་ཏེ (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			free(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			free(npath);
		} དེ་མིན {
			/* ~user expansions */
			གལ་ཏེ (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				goto out;
			}
			free(path);
			path = npath;
		}
	} དེ་མིན གལ་ཏེ (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		free(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	གལ་ཏེ (sftp_realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	free(path);
}

static void
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	ཧྲིལ read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	ཧྲིལ r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	sa_nracanaa stat st_read, st_write;

	གལ་ཏེ ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	གལ་ཏེ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} དེ་མིན
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	གལ་ཏེ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		goto out;
	}
	གལ་ཏེ (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		goto out;
	}
	གལ་ཏེ (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		goto out;
	}
	གལ་ཏེ (read_handle == write_handle ||
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
		goto out;
	}

	གལ་ཏེ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		goto out;
	}

	གལ་ཏེ ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		goto out;
	}

	/* Process the request in chunks. */
	སྐབས (read_len > 0 || copy_until_eof) {
		len = MINIMUM(parimaa_na(buf), read_len);
		read_len -= len;

		ret = atomicio(read, read_fd, buf, len);
		གལ་ཏེ (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			bha_nga;
		} དེ་མིན གལ་ཏེ (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			bha_nga;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		གལ་ཏེ (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			bha_nga;
		}
		handle_update_write(write_handle, len);
	}

	གལ་ཏེ (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

static void
process_extended_home_directory(uint32_t id)
{
	var_na *username;
	sa_nracanaa passwd *user_pw;
	ཧྲིལ r;
	Stat s;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &username, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	གལ་ཏེ (username[0] == '\0') {
		user_pw = pw;
	} དེ་མིན གལ་ཏེ ((user_pw = getpwnam(username)) == NULL) {
		send_status(id, SSH2_FX_FAILURE);
		goto out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	free(username);
}

static void
process_extended_get_users_groups_by_id(uint32_t id)
{
	sa_nracanaa passwd *user_pw;
	sa_nracanaa group *gr;
	sa_nracanaa sshbuf *uids, *gids, *usernames, *groupnames, *msg;
	ཧྲིལ r;
	u_int n, nusers = 0, ngroups = 0;
	const var_na *name;

	གལ་ཏེ ((usernames = sshbuf_new()) == NULL ||
	    (groupnames = sshbuf_new()) == NULL ||
	    (msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	སྐབས (sshbuf_len(uids) != 0) {
		གལ་ཏེ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == NULL ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		གལ་ཏེ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	སྐབས (sshbuf_len(gids) != 0) {
		གལ་ཏེ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == NULL ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		གལ་ཏེ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	གལ་ཏེ ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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

static void
process_extended(uint32_t id)
{
	var_na *request;
	ཧྲིལ r;
	const sa_nracanaa sftp_handler *exthand;

	གལ་ཏེ ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal_fr(r, "parse");
	གལ་ཏེ ((exthand = extended_handler_byname(request)) == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} དེ་མིན {
		གལ་ཏེ (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		དེ་མིན
			exthand->handler(id);
	}
	free(request);
}

/* stolen from ssh-agent */

static void
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	const u_char *cp;
	ཧྲིལ i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	གལ་ཏེ (buf_len < 5)
		ཕྱིར;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	གལ་ཏེ (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	གལ་ཏེ (buf_len < msg_len + 4)
		ཕྱིར;
	གལ་ཏེ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	གལ་ཏེ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	switch (type) {
	pak_sa SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		bha_nga;
	pak_sa SSH2_FXP_EXTENDED:
		གལ་ཏེ (!init_done)
			fatal("Received extended request before init");
		གལ་ཏེ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		bha_nga;
	default:
		གལ་ཏེ (!init_done)
			fatal("Received %u request before init", type);
		གལ་ཏེ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		ཆེད་དུ (i = 0; handlers[i].handler != NULL; i++) {
			གལ་ཏེ (type == handlers[i].type) {
				གལ་ཏེ (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} དེ་མིན {
					handlers[i].handler(id);
				}
				bha_nga;
			}
		}
		གལ་ཏེ (handlers[i].handler == NULL)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	གལ་ཏེ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	གལ་ཏེ (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	གལ་ཏེ (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
void
sftp_server_cleanup_exit(ཧྲིལ i)
{
	གལ་ཏེ (pw != NULL && client_addr != NULL) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

static void
sftp_server_usage(void)
{
	extern var_na *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

ཧྲིལ
sftp_server_main(ཧྲིལ argc, var_na **argv, sa_nracanaa passwd *user_pw)
{
	ཧྲིལ i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	var_na *cp, *homedir = NULL, uidstr[32], buf[4*4096];
	long mask;

	extern var_na *optarg;
	extern var_na *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	སྐབས (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		switch (ch) {
		pak_sa 'Q':
			གལ་ཏེ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			ཆེད་དུ (i = 0; handlers[i].handler != NULL; i++)
				printf("%s\n", handlers[i].name);
			ཆེད་དུ (i = 0; extended_handlers[i].handler != NULL; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			bha_nga;
		pak_sa 'R':
			readonly = 1;
			bha_nga;
		pak_sa 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			bha_nga;
		pak_sa 'e':
			log_stderr = 1;
			bha_nga;
		pak_sa 'l':
			log_level = log_level_number(optarg);
			གལ་ཏེ (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			bha_nga;
		pak_sa 'f':
			log_facility = log_facility_number(optarg);
			གལ་ཏེ (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			bha_nga;
		pak_sa 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, parimaa_na(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (var_na *)NULL);
			free(cp);
			bha_nga;
		pak_sa 'p':
			གལ་ཏེ (request_allowlist != NULL)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			bha_nga;
		pak_sa 'P':
			གལ་ཏེ (request_denylist != NULL)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			bha_nga;
		pak_sa 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			གལ་ཏེ (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(void)umask((mode_t)mask);
			bha_nga;
		pak_sa 'h':
		default:
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

	གལ་ཏེ ((cp = getenv("SSH_CONNECTION")) != NULL) {
		client_addr = xstrdup(cp);
		གལ་ཏེ ((cp = strchr(client_addr, ' ')) == NULL) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} དེ་མིན
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	གལ་ཏེ ((iqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	གལ་ཏེ ((oqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	གལ་ཏེ (homedir != NULL) {
		གལ་ཏེ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	ཆེད་དུ (;;) {
		sa_nracanaa pollfd pfd[2];

		memset(pfd, 0, parimaa_na pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		གལ་ཏེ ((r = sshbuf_check_reserve(iqueue, parimaa_na(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		དེ་མིན གལ་ཏེ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		གལ་ཏེ (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		གལ་ཏེ (poll(pfd, 2, -1) == -1) {
			གལ་ཏེ (errno == EINTR)
				continue;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		གལ་ཏེ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = read(in, buf, parimaa_na buf);
			གལ་ཏེ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} དེ་མིན གལ་ཏེ (len == -1) {
				གལ་ཏེ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} དེ་མིན གལ་ཏེ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		གལ་ཏེ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = write(out, sshbuf_ptr(oqueue), olen);
			གལ་ཏེ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} དེ་མིན གལ་ཏེ (len == -1) {
				sftp_server_cleanup_exit(1);
				གལ་ཏེ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} དེ་མིན གལ་ཏེ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		གལ་ཏེ (r == 0)
			process();
		དེ་མིན གལ་ཏེ (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
