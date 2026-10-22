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

char *sftp_realpath(const char *, char *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_MSG_LENGTH - 1024)

/* Our verbosity */
static LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
static struct passwd *pw = NULL;
static char *client_addr = NULL;

/* input and output queue */
struct sshbuf *iqueue;
struct sshbuf *oqueue;

/* Version of client */
static u_int version;

/* SSH2_FXP_INIT received */
static số_nguyên init_done;

/* Disable writes */
static số_nguyên readonly;

/* Requests that are allowed/denied */
static char *request_allowlist, *request_denylist;

/* portable attributes, etc. */
typedef struct Stat Stat;

struct Stat {
	char *name;
	char *long_name;
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

struct sftp_handler {
	const char *name;	/* user-visible name for fine-grained perms */
	const char *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	void (*handler)(uint32_t);
	số_nguyên does_write;		/* if nonzero, banned for readonly mode */
};

static const struct sftp_handler handlers[] = {
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
static const struct sftp_handler extended_handlers[] = {
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

static const struct sftp_handler *
extended_handler_byname(const char *name)
{
	số_nguyên i;

	cho (i = 0; extended_handlers[i].handler != NULL; i++) {
		nếu (strcmp(name, extended_handlers[i].ext_name) == 0)
			trả_về &extended_handlers[i];
	}
	trả_về NULL;
}

static số_nguyên
request_permitted(const struct sftp_handler *h)
{
	char *result;

	nếu (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		trả_về 0;
	}
	nếu (request_denylist != NULL &&
	    ((result = match_list(h->name, request_denylist, NULL))) != NULL) {
		free(result);
		verbose("Refusing denylisted %s request", h->name);
		trả_về 0;
	}
	nếu (request_allowlist != NULL &&
	    ((result = match_list(h->name, request_allowlist, NULL))) != NULL) {
		free(result);
		debug2("Permitting allowlisted %s request", h->name);
		trả_về 1;
	}
	nếu (request_allowlist != NULL) {
		verbose("Refusing non-allowlisted %s request", h->name);
		trả_về 0;
	}
	trả_về 1;
}

static số_nguyên
errno_to_portable(số_nguyên unixerrno)
{
	số_nguyên ret = 0;

	switch (unixerrno) {
	case 0:
		ret = SSH2_FX_OK;
		break;
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		break;
	case EPERM:
	case EACCES:
	case EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		break;
	case ENAMETOOLONG:
	case EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		break;
	case ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		break;
	default:
		ret = SSH2_FX_FAILURE;
		break;
	}
	trả_về ret;
}

static số_nguyên
flags_from_portable(số_nguyên pflags)
{
	số_nguyên flags = 0;

	nếu ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} không_thì nếu (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} không_thì nếu (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	nếu (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	nếu (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	nếu (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	nếu (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	trả_về flags;
}

static const char *
string_from_portable(số_nguyên pflags)
{
	static char ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		nếu (*ret != '\0')			\
			strlcat(ret, ",", sizeof(ret));	\
		strlcat(ret, str, sizeof(ret));		\
	}

	nếu (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	nếu (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	nếu (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	nếu (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	nếu (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	nếu (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	trả_về ret;
}

/* handle handles */

typedef struct Handle Handle;
struct Handle {
	số_nguyên use;
	DIR *dirp;
	số_nguyên fd;
	số_nguyên flags;
	char *name;
	uint64_t bytes_read, bytes_write;
	số_nguyên next_unused;
};

enum {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

static Handle *handles = NULL;
static u_int num_handles = 0;
static số_nguyên first_unused_handle = -1;

static void handle_unused(số_nguyên i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static số_nguyên
handle_new(số_nguyên use, const char *name, số_nguyên fd, số_nguyên flags, DIR *dirp)
{
	số_nguyên i;

	nếu (first_unused_handle == -1) {
		nếu (num_handles + 1 <= num_handles)
			trả_về -1;
		num_handles++;
		handles = xreallocarray(handles, num_handles, sizeof(Handle));
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

	trả_về i;
}

static số_nguyên
handle_is_ok(số_nguyên i, số_nguyên type)
{
	trả_về i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

static số_nguyên
handle_to_string(số_nguyên handle, u_char **stringp, số_nguyên *hlenp)
{
	nếu (stringp == NULL || hlenp == NULL)
		trả_về -1;
	*stringp = xmalloc(sizeof(int32_t));
	put_u32(*stringp, handle);
	*hlenp = sizeof(int32_t);
	trả_về 0;
}

static số_nguyên
handle_from_string(const u_char *handle, u_int hlen)
{
	số_nguyên val;

	nếu (hlen != sizeof(int32_t))
		trả_về -1;
	val = get_u32(handle);
	nếu (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		trả_về val;
	trả_về -1;
}

static char *
handle_to_name(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		trả_về handles[handle].name;
	trả_về NULL;
}

static DIR *
handle_to_dir(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_DIR))
		trả_về handles[handle].dirp;
	trả_về NULL;
}

static số_nguyên
handle_to_fd(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_FILE))
		trả_về handles[handle].fd;
	trả_về -1;
}

static số_nguyên
handle_to_flags(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_FILE))
		trả_về handles[handle].flags;
	trả_về 0;
}

static void
handle_update_read(số_nguyên handle, ssize_t bytes)
{
	nếu (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

static void
handle_update_write(số_nguyên handle, ssize_t bytes)
{
	nếu (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

static uint64_t
handle_bytes_read(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_FILE))
		trả_về (handles[handle].bytes_read);
	trả_về 0;
}

static uint64_t
handle_bytes_write(số_nguyên handle)
{
	nếu (handle_is_ok(handle, HANDLE_FILE))
		trả_về (handles[handle].bytes_write);
	trả_về 0;
}

static số_nguyên
handle_close(số_nguyên handle)
{
	số_nguyên ret = -1;

	nếu (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		free(handles[handle].name);
		handle_unused(handle);
	} không_thì nếu (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		free(handles[handle].name);
		handle_unused(handle);
	} không_thì {
		errno = ENOENT;
	}
	trả_về ret;
}

static void
handle_log_close(số_nguyên handle, char *emsg)
{
	nếu (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} không_thì {
		logit("%s%sclosedir \"%s\"",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle));
	}
}

static void
handle_log_exit(void)
{
	u_int i;

	cho (i = 0; i < num_handles; i++)
		nếu (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

static số_nguyên
get_handle(struct sshbuf *queue, số_nguyên *hp)
{
	u_char *handle;
	số_nguyên r;
	size_t hlen;

	*hp = -1;
	nếu ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		trả_về r;
	nếu (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	free(handle);
	trả_về 0;
}

/* send replies */

static void
send_msg(struct sshbuf *m)
{
	số_nguyên r;

	nếu ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

static const char *
status_to_message(uint32_t status)
{
	static const char * const status_messages[] = {
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
	trả_về (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

static void
send_status_errmsg(uint32_t id, uint32_t status, const char *errmsg)
{
	struct sshbuf *msg;
	số_nguyên r;

	debug3("request %u: sent status %u", id, status);
	nếu (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal_fr(r, "compose");
	nếu (version >= 3) {
		nếu ((r = sshbuf_put_cstring(msg, errmsg == NULL ?
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
send_data_or_handle(char type, uint32_t id, const u_char *data, số_nguyên dlen)
{
	struct sshbuf *msg;
	số_nguyên r;

	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_data(uint32_t id, const u_char *data, số_nguyên dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(uint32_t id, số_nguyên handle)
{
	u_char *string;
	số_nguyên hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	free(string);
}

static void
send_names(uint32_t id, số_nguyên count, const Stat *stats)
{
	struct sshbuf *msg;
	số_nguyên i, r;

	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, count);
	cho (i = 0; i < count; i++) {
		nếu ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
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
	struct sshbuf *msg;
	số_nguyên r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_statvfs(uint32_t id, struct statvfs *st)
{
	struct sshbuf *msg;
	uint64_t flag;
	số_nguyên r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
static số_nguyên
compose_extension(struct sshbuf *msg, const char *name, const char *ver)
{
	số_nguyên r;
	const struct sftp_handler *exthnd;

	nếu ((exthnd = extended_handler_byname(name)) == NULL)
		fatal_f("internal error: no handler for %s", name);
	nếu (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		trả_về 0;
	}
	nếu ((r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	trả_về 0;
}

/* parse incoming */

static void
process_init(void)
{
	struct sshbuf *msg;
	số_nguyên r;

	nếu ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
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
	char *name;
	số_nguyên r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	nếu (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} không_thì {
		fd = open(name, flags, mode);
		nếu (fd == -1) {
			status = errno_to_portable(errno);
		} không_thì {
			handle = handle_new(HANDLE_FILE, name, fd, flags, NULL);
			nếu (handle < 0) {
				close(fd);
			} không_thì {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	nếu (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_close(uint32_t id)
{
	số_nguyên r, handle, ret, status = SSH2_FX_FAILURE;

	nếu ((r = get_handle(iqueue, &handle)) != 0)
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
	số_nguyên r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	nếu ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	nếu ((fd = handle_to_fd(handle)) == -1)
		goto out;
	nếu (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	nếu (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		nếu ((buf = realloc(buf, len)) == NULL)
			fatal_f("realloc failed");
		buflen = len;
	}
	nếu (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	}
	nếu (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} không_thì nếu ((ret = read(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	} không_thì nếu (ret == 0) {
		status = SSH2_FX_EOF;
		goto out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	nếu (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	số_nguyên r, handle, fd, ret, status;
	u_char *data;

	nếu ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	nếu (fd < 0)
		status = SSH2_FX_FAILURE;
	không_thì {
		nếu (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} không_thì {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			nếu (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} không_thì nếu ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} không_thì {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	free(data);
}

static void
process_do_stat(uint32_t id, số_nguyên do_lstat)
{
	Attrib a;
	struct stat st;
	char *name;
	số_nguyên r, status = SSH2_FX_FAILURE;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	nếu (r == -1) {
		status = errno_to_portable(errno);
	} không_thì {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	nếu (status != SSH2_FX_OK)
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
	struct stat st;
	số_nguyên fd, r, handle, status = SSH2_FX_FAILURE;

	nếu ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	nếu (fd >= 0) {
		r = fstat(fd, &st);
		nếu (r == -1) {
			status = errno_to_portable(errno);
		} không_thì {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	nếu (status != SSH2_FX_OK)
		send_status(id, status);
}

static struct timeval *
attrib_to_tv(const Attrib *a)
{
	static struct timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	trả_về tv;
}

static struct timespec *
attrib_to_ts(const Attrib *a)
{
	static struct timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	trả_về ts;
}

static void
process_setstat(uint32_t id)
{
	Attrib a;
	char *name;
	số_nguyên r, status = SSH2_FX_OK;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	nếu (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	free(name);
}

static void
process_fsetstat(uint32_t id)
{
	Attrib a;
	số_nguyên handle, fd, r;
	số_nguyên status = SSH2_FX_OK;

	nếu ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	nếu (fd < 0)
		status = SSH2_FX_FAILURE;
	không_thì {
		char *name = handle_to_name(handle);

		nếu (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			nếu (r == -1)
				status = errno_to_portable(errno);
		}
		nếu (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#không_thì
			r = chmod(name, a.perm & 07777);
#endif
			nếu (r == -1)
				status = errno_to_portable(errno);
		}
		nếu (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			char buf[64];
			time_t t = a.mtime;

			strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#không_thì
			r = utimes(name, attrib_to_tv(&a));
#endif
			nếu (r == -1)
				status = errno_to_portable(errno);
		}
		nếu (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#không_thì
			r = chown(name, a.uid, a.gid);
#endif
			nếu (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

static void
process_opendir(uint32_t id)
{
	DIR *dirp = NULL;
	char *path;
	số_nguyên r, handle, status = SSH2_FX_FAILURE;

	nếu ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	nếu (dirp == NULL) {
		status = errno_to_portable(errno);
	} không_thì {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		nếu (handle < 0) {
			closedir(dirp);
		} không_thì {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	nếu (status != SSH2_FX_OK)
		send_status(id, status);
	free(path);
}

static void
process_readdir(uint32_t id)
{
	DIR *dirp;
	struct dirent *dp;
	char *path;
	số_nguyên r, handle;

	nếu ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	nếu (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} không_thì {
		struct stat st;
		char *pathname;
		Stat *stats;
		số_nguyên nstats = 10, count = 0, i;

		stats = xcalloc(nstats, sizeof(Stat));
		trong_khi ((dp = readdir(dirp)) != NULL) {
			nếu (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, sizeof(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			free(pathname);
			nếu (r == -1)
				continue;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st,
			    0, 0, NULL, NULL);
			count++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			nếu (count == 100)
				break;
		}
		nếu (count > 0) {
			send_names(id, count, stats);
			cho (i = 0; i < count; i++) {
				free(stats[i].name);
				free(stats[i].long_name);
			}
		} không_thì {
			send_status(id, SSH2_FX_EOF);
		}
		free(stats);
	}
}

static void
process_remove(uint32_t id)
{
	char *name;
	số_nguyên r, status = SSH2_FX_FAILURE;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
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
	char *name;
	số_nguyên r, mode, status = SSH2_FX_FAILURE;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
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
	char *name;
	số_nguyên r, status;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
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
	char resolvedname[PATH_MAX];
	char *path;
	số_nguyên r;

	nếu ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	nếu (path[0] == '\0') {
		free(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	nếu (sftp_realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} không_thì {
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
	char *oldpath, *newpath;
	số_nguyên r, status;
	struct stat sb;

	nếu ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	nếu (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	không_thì nếu (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		nếu (link(oldpath, newpath) == -1) {
			nếu (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				struct stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				nếu (stat(newpath, &st) == -1) {
					nếu (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					không_thì
						status = SSH2_FX_OK;
				}
			} không_thì {
				status = errno_to_portable(errno);
			}
		} không_thì nếu (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} không_thì
			status = SSH2_FX_OK;
	} không_thì nếu (stat(newpath, &sb) == -1) {
		nếu (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		không_thì
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_readlink(uint32_t id)
{
	số_nguyên r, len;
	char buf[PATH_MAX];
	char *path;

	nếu ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	nếu ((len = readlink(path, buf, sizeof(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	không_thì {
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
	char *oldpath, *newpath;
	số_nguyên r, status;

	nếu ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	char *oldpath, *newpath;
	số_nguyên r, status;

	nếu ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	char *path;
	struct statvfs st;
	số_nguyên r;

	nếu ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	nếu (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	không_thì
		send_statvfs(id, &st);
	free(path);
}

static void
process_extended_fstatvfs(uint32_t id)
{
	số_nguyên r, handle, fd;
	struct statvfs st;

	nếu ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	nếu ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		trả_về;
	}
	nếu (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	không_thì
		send_statvfs(id, &st);
}

static void
process_extended_hardlink(uint32_t id)
{
	char *oldpath, *newpath;
	số_nguyên r, status;

	nếu ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	số_nguyên handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	nếu ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	nếu ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	không_thì nếu (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

static void
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	char *name;
	số_nguyên r, status = SSH2_FX_OK;

	nếu ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	nếu (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		goto out;
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
	nếu (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		nếu (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	free(name);
}

static void
process_extended_limits(uint32_t id)
{
	struct sshbuf *msg;
	số_nguyên r;
	uint64_t nfiles = 0;
#nếu defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlim;
#endif

	debug("request %u: limits", id);

#nếu defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	nếu (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	nếu ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
	char cwd[PATH_MAX], resolvedname[PATH_MAX];
	char *path, *npath;
	số_nguyên r;
	Stat s;

	nếu ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	nếu (getcwd(cwd, sizeof(cwd)) == NULL) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	nếu (path[0] == '\0') {
		/* empty path */
		free(path);
		path = xstrdup(".");
	} không_thì nếu (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		nếu (strcmp(path, "~") == 0) {
			free(path);
			path = xstrdup(cwd);
		} không_thì nếu (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			free(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			free(npath);
		} không_thì {
			/* ~user expansions */
			nếu (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				goto out;
			}
			free(path);
			path = npath;
		}
	} không_thì nếu (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		free(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	nếu (sftp_realpath(path, resolvedname) == NULL) {
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
	số_nguyên read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	số_nguyên r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	struct stat st_read, st_write;

	nếu ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	nếu (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} không_thì
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	nếu (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		goto out;
	}
	nếu (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		goto out;
	}
	nếu (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		goto out;
	}
	nếu (read_handle == write_handle ||
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

	nếu (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		goto out;
	}

	nếu ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		goto out;
	}

	/* Process the request in chunks. */
	trong_khi (read_len > 0 || copy_until_eof) {
		len = MINIMUM(sizeof(buf), read_len);
		read_len -= len;

		ret = atomicio(read, read_fd, buf, len);
		nếu (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			break;
		} không_thì nếu (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			break;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		nếu (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			break;
		}
		handle_update_write(write_handle, len);
	}

	nếu (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

static void
process_extended_home_directory(uint32_t id)
{
	char *username;
	struct passwd *user_pw;
	số_nguyên r;
	Stat s;

	nếu ((r = sshbuf_get_cstring(iqueue, &username, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	nếu (username[0] == '\0') {
		user_pw = pw;
	} không_thì nếu ((user_pw = getpwnam(username)) == NULL) {
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
	struct passwd *user_pw;
	struct group *gr;
	struct sshbuf *uids, *gids, *usernames, *groupnames, *msg;
	số_nguyên r;
	u_int n, nusers = 0, ngroups = 0;
	const char *name;

	nếu ((usernames = sshbuf_new()) == NULL ||
	    (groupnames = sshbuf_new()) == NULL ||
	    (msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	trong_khi (sshbuf_len(uids) != 0) {
		nếu ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == NULL ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		nếu ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	trong_khi (sshbuf_len(gids) != 0) {
		nếu ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == NULL ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		nếu ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	nếu ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
	char *request;
	số_nguyên r;
	const struct sftp_handler *exthand;

	nếu ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal_fr(r, "parse");
	nếu ((exthand = extended_handler_byname(request)) == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} không_thì {
		nếu (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		không_thì
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
	số_nguyên i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	nếu (buf_len < 5)
		trả_về;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	nếu (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	nếu (buf_len < msg_len + 4)
		trả_về;
	nếu ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	nếu ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		break;
	case SSH2_FXP_EXTENDED:
		nếu (!init_done)
			fatal("Received extended request before init");
		nếu ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		break;
	default:
		nếu (!init_done)
			fatal("Received %u request before init", type);
		nếu ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		cho (i = 0; handlers[i].handler != NULL; i++) {
			nếu (type == handlers[i].type) {
				nếu (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} không_thì {
					handlers[i].handler(id);
				}
				break;
			}
		}
		nếu (handlers[i].handler == NULL)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	nếu (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	nếu (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	nếu (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
void
sftp_server_cleanup_exit(số_nguyên i)
{
	nếu (pw != NULL && client_addr != NULL) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

static void
sftp_server_usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

số_nguyên
sftp_server_main(số_nguyên argc, char **argv, struct passwd *user_pw)
{
	số_nguyên i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	char *cp, *homedir = NULL, uidstr[32], buf[4*4096];
	long mask;

	extern char *optarg;
	extern char *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	trong_khi (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		switch (ch) {
		case 'Q':
			nếu (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			cho (i = 0; handlers[i].handler != NULL; i++)
				printf("%s\n", handlers[i].name);
			cho (i = 0; extended_handlers[i].handler != NULL; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			break;
		case 'R':
			readonly = 1;
			break;
		case 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			break;
		case 'e':
			log_stderr = 1;
			break;
		case 'l':
			log_level = log_level_number(optarg);
			nếu (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			log_facility = log_facility_number(optarg);
			nếu (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			break;
		case 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, sizeof(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (char *)NULL);
			free(cp);
			break;
		case 'p':
			nếu (request_allowlist != NULL)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			break;
		case 'P':
			nếu (request_denylist != NULL)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			break;
		case 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			nếu (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(void)umask((mode_t)mask);
			break;
		case 'h':
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

	nếu ((cp = getenv("SSH_CONNECTION")) != NULL) {
		client_addr = xstrdup(cp);
		nếu ((cp = strchr(client_addr, ' ')) == NULL) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} không_thì
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	nếu ((iqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	nếu ((oqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	nếu (homedir != NULL) {
		nếu (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	cho (;;) {
		struct pollfd pfd[2];

		memset(pfd, 0, sizeof pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		nếu ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		không_thì nếu (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		nếu (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		nếu (poll(pfd, 2, -1) == -1) {
			nếu (errno == EINTR)
				continue;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		nếu (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = read(in, buf, sizeof buf);
			nếu (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} không_thì nếu (len == -1) {
				nếu (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} không_thì nếu ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		nếu (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = write(out, sshbuf_ptr(oqueue), olen);
			nếu (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} không_thì nếu (len == -1) {
				sftp_server_cleanup_exit(1);
				nếu (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} không_thì nếu ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		nếu (r == 0)
			process();
		không_thì nếu (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
