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
static 정수 init_done;

/* Disable writes */
static 정수 readonly;

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
	정수 does_write;		/* if nonzero, banned for readonly mode */
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
	정수 i;

	위해 (i = 0; extended_handlers[i].handler != NULL; i++) {
		만약 (strcmp(name, extended_handlers[i].ext_name) == 0)
			반환 &extended_handlers[i];
	}
	반환 NULL;
}

static 정수
request_permitted(const struct sftp_handler *h)
{
	char *result;

	만약 (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		반환 0;
	}
	만약 (request_denylist != NULL &&
	    ((result = match_list(h->name, request_denylist, NULL))) != NULL) {
		free(result);
		verbose("Refusing denylisted %s request", h->name);
		반환 0;
	}
	만약 (request_allowlist != NULL &&
	    ((result = match_list(h->name, request_allowlist, NULL))) != NULL) {
		free(result);
		debug2("Permitting allowlisted %s request", h->name);
		반환 1;
	}
	만약 (request_allowlist != NULL) {
		verbose("Refusing non-allowlisted %s request", h->name);
		반환 0;
	}
	반환 1;
}

static 정수
errno_to_portable(정수 unixerrno)
{
	정수 ret = 0;

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
	반환 ret;
}

static 정수
flags_from_portable(정수 pflags)
{
	정수 flags = 0;

	만약 ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} 아니면 만약 (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} 아니면 만약 (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	만약 (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	만약 (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	만약 (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	만약 (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	반환 flags;
}

static const char *
string_from_portable(정수 pflags)
{
	static char ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		만약 (*ret != '\0')			\
			strlcat(ret, ",", sizeof(ret));	\
		strlcat(ret, str, sizeof(ret));		\
	}

	만약 (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	만약 (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	만약 (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	만약 (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	만약 (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	만약 (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	반환 ret;
}

/* handle handles */

typedef struct Handle Handle;
struct Handle {
	정수 use;
	DIR *dirp;
	정수 fd;
	정수 flags;
	char *name;
	uint64_t bytes_read, bytes_write;
	정수 next_unused;
};

enum {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

static Handle *handles = NULL;
static u_int num_handles = 0;
static 정수 first_unused_handle = -1;

static void handle_unused(정수 i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static 정수
handle_new(정수 use, const char *name, 정수 fd, 정수 flags, DIR *dirp)
{
	정수 i;

	만약 (first_unused_handle == -1) {
		만약 (num_handles + 1 <= num_handles)
			반환 -1;
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

	반환 i;
}

static 정수
handle_is_ok(정수 i, 정수 type)
{
	반환 i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

static 정수
handle_to_string(정수 handle, u_char **stringp, 정수 *hlenp)
{
	만약 (stringp == NULL || hlenp == NULL)
		반환 -1;
	*stringp = xmalloc(sizeof(int32_t));
	put_u32(*stringp, handle);
	*hlenp = sizeof(int32_t);
	반환 0;
}

static 정수
handle_from_string(const u_char *handle, u_int hlen)
{
	정수 val;

	만약 (hlen != sizeof(int32_t))
		반환 -1;
	val = get_u32(handle);
	만약 (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		반환 val;
	반환 -1;
}

static char *
handle_to_name(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		반환 handles[handle].name;
	반환 NULL;
}

static DIR *
handle_to_dir(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_DIR))
		반환 handles[handle].dirp;
	반환 NULL;
}

static 정수
handle_to_fd(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_FILE))
		반환 handles[handle].fd;
	반환 -1;
}

static 정수
handle_to_flags(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_FILE))
		반환 handles[handle].flags;
	반환 0;
}

static void
handle_update_read(정수 handle, ssize_t bytes)
{
	만약 (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

static void
handle_update_write(정수 handle, ssize_t bytes)
{
	만약 (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

static uint64_t
handle_bytes_read(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_FILE))
		반환 (handles[handle].bytes_read);
	반환 0;
}

static uint64_t
handle_bytes_write(정수 handle)
{
	만약 (handle_is_ok(handle, HANDLE_FILE))
		반환 (handles[handle].bytes_write);
	반환 0;
}

static 정수
handle_close(정수 handle)
{
	정수 ret = -1;

	만약 (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		free(handles[handle].name);
		handle_unused(handle);
	} 아니면 만약 (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		free(handles[handle].name);
		handle_unused(handle);
	} 아니면 {
		errno = ENOENT;
	}
	반환 ret;
}

static void
handle_log_close(정수 handle, char *emsg)
{
	만약 (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} 아니면 {
		logit("%s%sclosedir \"%s\"",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle));
	}
}

static void
handle_log_exit(void)
{
	u_int i;

	위해 (i = 0; i < num_handles; i++)
		만약 (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

static 정수
get_handle(struct sshbuf *queue, 정수 *hp)
{
	u_char *handle;
	정수 r;
	size_t hlen;

	*hp = -1;
	만약 ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		반환 r;
	만약 (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	free(handle);
	반환 0;
}

/* send replies */

static void
send_msg(struct sshbuf *m)
{
	정수 r;

	만약 ((r = sshbuf_put_stringb(oqueue, m)) != 0)
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
	반환 (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

static void
send_status_errmsg(uint32_t id, uint32_t status, const char *errmsg)
{
	struct sshbuf *msg;
	정수 r;

	debug3("request %u: sent status %u", id, status);
	만약 (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal_fr(r, "compose");
	만약 (version >= 3) {
		만약 ((r = sshbuf_put_cstring(msg, errmsg == NULL ?
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
send_data_or_handle(char type, uint32_t id, const u_char *data, 정수 dlen)
{
	struct sshbuf *msg;
	정수 r;

	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_data(uint32_t id, const u_char *data, 정수 dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(uint32_t id, 정수 handle)
{
	u_char *string;
	정수 hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	free(string);
}

static void
send_names(uint32_t id, 정수 count, const Stat *stats)
{
	struct sshbuf *msg;
	정수 i, r;

	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, count);
	위해 (i = 0; i < count; i++) {
		만약 ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
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
	정수 r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
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
	정수 r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
static 정수
compose_extension(struct sshbuf *msg, const char *name, const char *ver)
{
	정수 r;
	const struct sftp_handler *exthnd;

	만약 ((exthnd = extended_handler_byname(name)) == NULL)
		fatal_f("internal error: no handler for %s", name);
	만약 (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		반환 0;
	}
	만약 ((r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	반환 0;
}

/* parse incoming */

static void
process_init(void)
{
	struct sshbuf *msg;
	정수 r;

	만약 ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
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
	정수 r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	만약 (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} 아니면 {
		fd = open(name, flags, mode);
		만약 (fd == -1) {
			status = errno_to_portable(errno);
		} 아니면 {
			handle = handle_new(HANDLE_FILE, name, fd, flags, NULL);
			만약 (handle < 0) {
				close(fd);
			} 아니면 {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	만약 (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_close(uint32_t id)
{
	정수 r, handle, ret, status = SSH2_FX_FAILURE;

	만약 ((r = get_handle(iqueue, &handle)) != 0)
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
	정수 r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	만약 ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	만약 ((fd = handle_to_fd(handle)) == -1)
		goto out;
	만약 (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	만약 (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		만약 ((buf = realloc(buf, len)) == NULL)
			fatal_f("realloc failed");
		buflen = len;
	}
	만약 (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	}
	만약 (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} 아니면 만약 ((ret = read(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		goto out;
	} 아니면 만약 (ret == 0) {
		status = SSH2_FX_EOF;
		goto out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	만약 (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	정수 r, handle, fd, ret, status;
	u_char *data;

	만약 ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	만약 (fd < 0)
		status = SSH2_FX_FAILURE;
	아니면 {
		만약 (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} 아니면 {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			만약 (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} 아니면 만약 ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} 아니면 {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	free(data);
}

static void
process_do_stat(uint32_t id, 정수 do_lstat)
{
	Attrib a;
	struct stat st;
	char *name;
	정수 r, status = SSH2_FX_FAILURE;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	만약 (r == -1) {
		status = errno_to_portable(errno);
	} 아니면 {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	만약 (status != SSH2_FX_OK)
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
	정수 fd, r, handle, status = SSH2_FX_FAILURE;

	만약 ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	만약 (fd >= 0) {
		r = fstat(fd, &st);
		만약 (r == -1) {
			status = errno_to_portable(errno);
		} 아니면 {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	만약 (status != SSH2_FX_OK)
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
	반환 tv;
}

static struct timespec *
attrib_to_ts(const Attrib *a)
{
	static struct timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	반환 ts;
}

static void
process_setstat(uint32_t id)
{
	Attrib a;
	char *name;
	정수 r, status = SSH2_FX_OK;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	만약 (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	free(name);
}

static void
process_fsetstat(uint32_t id)
{
	Attrib a;
	정수 handle, fd, r;
	정수 status = SSH2_FX_OK;

	만약 ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	만약 (fd < 0)
		status = SSH2_FX_FAILURE;
	아니면 {
		char *name = handle_to_name(handle);

		만약 (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			만약 (r == -1)
				status = errno_to_portable(errno);
		}
		만약 (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#아니면
			r = chmod(name, a.perm & 07777);
#endif
			만약 (r == -1)
				status = errno_to_portable(errno);
		}
		만약 (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			char buf[64];
			time_t t = a.mtime;

			strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#아니면
			r = utimes(name, attrib_to_tv(&a));
#endif
			만약 (r == -1)
				status = errno_to_portable(errno);
		}
		만약 (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#아니면
			r = chown(name, a.uid, a.gid);
#endif
			만약 (r == -1)
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
	정수 r, handle, status = SSH2_FX_FAILURE;

	만약 ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	만약 (dirp == NULL) {
		status = errno_to_portable(errno);
	} 아니면 {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		만약 (handle < 0) {
			closedir(dirp);
		} 아니면 {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	만약 (status != SSH2_FX_OK)
		send_status(id, status);
	free(path);
}

static void
process_readdir(uint32_t id)
{
	DIR *dirp;
	struct dirent *dp;
	char *path;
	정수 r, handle;

	만약 ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	만약 (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} 아니면 {
		struct stat st;
		char *pathname;
		Stat *stats;
		정수 nstats = 10, count = 0, i;

		stats = xcalloc(nstats, sizeof(Stat));
		동안 ((dp = readdir(dirp)) != NULL) {
			만약 (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, sizeof(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			free(pathname);
			만약 (r == -1)
				continue;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st,
			    0, 0, NULL, NULL);
			count++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			만약 (count == 100)
				break;
		}
		만약 (count > 0) {
			send_names(id, count, stats);
			위해 (i = 0; i < count; i++) {
				free(stats[i].name);
				free(stats[i].long_name);
			}
		} 아니면 {
			send_status(id, SSH2_FX_EOF);
		}
		free(stats);
	}
}

static void
process_remove(uint32_t id)
{
	char *name;
	정수 r, status = SSH2_FX_FAILURE;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
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
	정수 r, mode, status = SSH2_FX_FAILURE;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
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
	정수 r, status;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
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
	정수 r;

	만약 ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	만약 (path[0] == '\0') {
		free(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	만약 (sftp_realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} 아니면 {
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
	정수 r, status;
	struct stat sb;

	만약 ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	만약 (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	아니면 만약 (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		만약 (link(oldpath, newpath) == -1) {
			만약 (errno == EOPNOTSUPP || errno == ENOSYS
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
				만약 (stat(newpath, &st) == -1) {
					만약 (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					아니면
						status = SSH2_FX_OK;
				}
			} 아니면 {
				status = errno_to_portable(errno);
			}
		} 아니면 만약 (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} 아니면
			status = SSH2_FX_OK;
	} 아니면 만약 (stat(newpath, &sb) == -1) {
		만약 (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		아니면
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_readlink(uint32_t id)
{
	정수 r, len;
	char buf[PATH_MAX];
	char *path;

	만약 ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	만약 ((len = readlink(path, buf, sizeof(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	아니면 {
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
	정수 r, status;

	만약 ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	정수 r, status;

	만약 ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	정수 r;

	만약 ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	만약 (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	아니면
		send_statvfs(id, &st);
	free(path);
}

static void
process_extended_fstatvfs(uint32_t id)
{
	정수 r, handle, fd;
	struct statvfs st;

	만약 ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	만약 ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		반환;
	}
	만약 (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	아니면
		send_statvfs(id, &st);
}

static void
process_extended_hardlink(uint32_t id)
{
	char *oldpath, *newpath;
	정수 r, status;

	만약 ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
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
	정수 handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	만약 ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	만약 ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	아니면 만약 (handle_is_ok(handle, HANDLE_FILE)) {
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
	정수 r, status = SSH2_FX_OK;

	만약 ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	만약 (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		goto out;
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		만약 (r == -1)
			status = errno_to_portable(errno);
	}
	만약 (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		만약 (r == -1)
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
	정수 r;
	uint64_t nfiles = 0;
#만약 defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlim;
#endif

	debug("request %u: limits", id);

#만약 defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	만약 (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	만약 ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
	정수 r;
	Stat s;

	만약 ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal_fr(r, "parse");
	만약 (getcwd(cwd, sizeof(cwd)) == NULL) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	만약 (path[0] == '\0') {
		/* empty path */
		free(path);
		path = xstrdup(".");
	} 아니면 만약 (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		만약 (strcmp(path, "~") == 0) {
			free(path);
			path = xstrdup(cwd);
		} 아니면 만약 (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			free(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			free(npath);
		} 아니면 {
			/* ~user expansions */
			만약 (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				goto out;
			}
			free(path);
			path = npath;
		}
	} 아니면 만약 (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		free(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	만약 (sftp_realpath(path, resolvedname) == NULL) {
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
	정수 read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	정수 r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	struct stat st_read, st_write;

	만약 ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	만약 (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} 아니면
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	만약 (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		goto out;
	}
	만약 (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		goto out;
	}
	만약 (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		goto out;
	}
	만약 (read_handle == write_handle ||
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

	만약 (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		goto out;
	}

	만약 ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		goto out;
	}

	/* Process the request in chunks. */
	동안 (read_len > 0 || copy_until_eof) {
		len = MINIMUM(sizeof(buf), read_len);
		read_len -= len;

		ret = atomicio(read, read_fd, buf, len);
		만약 (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			break;
		} 아니면 만약 (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			break;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		만약 (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			break;
		}
		handle_update_write(write_handle, len);
	}

	만약 (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

static void
process_extended_home_directory(uint32_t id)
{
	char *username;
	struct passwd *user_pw;
	정수 r;
	Stat s;

	만약 ((r = sshbuf_get_cstring(iqueue, &username, NULL)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	만약 (username[0] == '\0') {
		user_pw = pw;
	} 아니면 만약 ((user_pw = getpwnam(username)) == NULL) {
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
	정수 r;
	u_int n, nusers = 0, ngroups = 0;
	const char *name;

	만약 ((usernames = sshbuf_new()) == NULL ||
	    (groupnames = sshbuf_new()) == NULL ||
	    (msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	동안 (sshbuf_len(uids) != 0) {
		만약 ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == NULL ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		만약 ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	동안 (sshbuf_len(gids) != 0) {
		만약 ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == NULL ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		만약 ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	만약 ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
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
	정수 r;
	const struct sftp_handler *exthand;

	만약 ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal_fr(r, "parse");
	만약 ((exthand = extended_handler_byname(request)) == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} 아니면 {
		만약 (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		아니면
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
	정수 i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	만약 (buf_len < 5)
		반환;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	만약 (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	만약 (buf_len < msg_len + 4)
		반환;
	만약 ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	만약 ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		break;
	case SSH2_FXP_EXTENDED:
		만약 (!init_done)
			fatal("Received extended request before init");
		만약 ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		break;
	default:
		만약 (!init_done)
			fatal("Received %u request before init", type);
		만약 ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		위해 (i = 0; handlers[i].handler != NULL; i++) {
			만약 (type == handlers[i].type) {
				만약 (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} 아니면 {
					handlers[i].handler(id);
				}
				break;
			}
		}
		만약 (handlers[i].handler == NULL)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	만약 (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	만약 (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	만약 (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
void
sftp_server_cleanup_exit(정수 i)
{
	만약 (pw != NULL && client_addr != NULL) {
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

정수
sftp_server_main(정수 argc, char **argv, struct passwd *user_pw)
{
	정수 i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	char *cp, *homedir = NULL, uidstr[32], buf[4*4096];
	long mask;

	extern char *optarg;
	extern char *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	동안 (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		switch (ch) {
		case 'Q':
			만약 (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			위해 (i = 0; handlers[i].handler != NULL; i++)
				printf("%s\n", handlers[i].name);
			위해 (i = 0; extended_handlers[i].handler != NULL; i++)
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
			만약 (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			log_facility = log_facility_number(optarg);
			만약 (log_facility == SYSLOG_FACILITY_NOT_SET)
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
			만약 (request_allowlist != NULL)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			break;
		case 'P':
			만약 (request_denylist != NULL)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			break;
		case 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			만약 (mask < 0 || mask > 0777 || *cp != '\0' ||
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

	만약 ((cp = getenv("SSH_CONNECTION")) != NULL) {
		client_addr = xstrdup(cp);
		만약 ((cp = strchr(client_addr, ' ')) == NULL) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} 아니면
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	만약 ((iqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	만약 ((oqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	만약 (homedir != NULL) {
		만약 (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	위해 (;;) {
		struct pollfd pfd[2];

		memset(pfd, 0, sizeof pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		만약 ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		아니면 만약 (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		만약 (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		만약 (poll(pfd, 2, -1) == -1) {
			만약 (errno == EINTR)
				continue;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		만약 (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = read(in, buf, sizeof buf);
			만약 (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} 아니면 만약 (len == -1) {
				만약 (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} 아니면 만약 ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		만약 (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = write(out, sshbuf_ptr(oqueue), olen);
			만약 (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} 아니면 만약 (len == -1) {
				sftp_server_cleanup_exit(1);
				만약 (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} 아니면 만약 ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		만약 (r == 0)
			process();
		아니면 만약 (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
