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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/resource.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/statvfs.h>

#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "uidswap.h"

#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "sftp-common.h"

বর্ণ *sftp_realpath(ধ্রুব বর্ণ *, বর্ণ *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_বার্তা_LENGTH - 1024)

/* Our verbosity */
স্থির LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
স্থির সংরচনা passwd *pw = রিক্ত;
স্থির বর্ণ *client_addr = রিক্ত;

/* input and output queue */
সংরচনা sshbuf *iqueue;
সংরচনা sshbuf *oqueue;

/* Version of client */
স্থির u_int version;

/* SSH2_FXP_INIT received */
স্থির পূর্ণাঙ্ক init_done;

/* Disable writes */
স্থির পূর্ণাঙ্ক readonly;

/* Requests that are allowed/denied */
স্থির বর্ণ *request_allowlist, *request_denylist;

/* portable attributes, etc. */
প্রকারনির্দেশ সংরচনা Stat Stat;

সংরচনা Stat {
	বর্ণ *name;
	বর্ণ *long_name;
	Attrib attrib;
};

/* Packet handlers */
স্থির শূন্য process_open(uint32_t id);
স্থির শূন্য process_close(uint32_t id);
স্থির শূন্য process_read(uint32_t id);
স্থির শূন্য process_write(uint32_t id);
স্থির শূন্য process_stat(uint32_t id);
স্থির শূন্য process_lstat(uint32_t id);
স্থির শূন্য process_fstat(uint32_t id);
স্থির শূন্য process_setstat(uint32_t id);
স্থির শূন্য process_fsetstat(uint32_t id);
স্থির শূন্য process_opendir(uint32_t id);
স্থির শূন্য process_readdir(uint32_t id);
স্থির শূন্য process_remove(uint32_t id);
স্থির শূন্য process_mkdir(uint32_t id);
স্থির শূন্য process_rmdir(uint32_t id);
স্থির শূন্য process_realpath(uint32_t id);
স্থির শূন্য process_rename(uint32_t id);
স্থির শূন্য process_readlink(uint32_t id);
স্থির শূন্য process_symlink(uint32_t id);
স্থির শূন্য process_extended_posix_rename(uint32_t id);
স্থির শূন্য process_extended_statvfs(uint32_t id);
স্থির শূন্য process_extended_fstatvfs(uint32_t id);
স্থির শূন্য process_extended_hardlink(uint32_t id);
স্থির শূন্য process_extended_fsync(uint32_t id);
স্থির শূন্য process_extended_lsetstat(uint32_t id);
স্থির শূন্য process_extended_limits(uint32_t id);
স্থির শূন্য process_extended_expand(uint32_t id);
স্থির শূন্য process_extended_copy_data(uint32_t id);
স্থির শূন্য process_extended_home_directory(uint32_t id);
স্থির শূন্য process_extended_get_users_groups_by_id(uint32_t id);
স্থির শূন্য process_extended(uint32_t id);

সংরচনা sftp_handler {
	ধ্রুব বর্ণ *name;	/* user-visible name for fine-grained perms */
	ধ্রুব বর্ণ *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	শূন্য (*handler)(uint32_t);
	পূর্ণাঙ্ক does_write;		/* if nonzero, banned for readonly mode */
};

স্থির ধ্রুব সংরচনা sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", রিক্ত, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", রিক্ত, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", রিক্ত, SSH2_FXP_READ, process_read, 0 },
	{ "write", রিক্ত, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", রিক্ত, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", রিক্ত, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", রিক্ত, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", রিক্ত, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", রিক্ত, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", রিক্ত, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", রিক্ত, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", রিক্ত, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", রিক্ত, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", রিক্ত, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", রিক্ত, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", রিক্ত, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", রিক্ত, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", রিক্ত, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ রিক্ত, রিক্ত, 0, রিক্ত, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
স্থির ধ্রুব সংরচনা sftp_handler extended_handlers[] = {
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
	{ রিক্ত, রিক্ত, 0, রিক্ত, 0 }
};

স্থির ধ্রুব সংরচনা sftp_handler *
extended_handler_byname(ধ্রুব বর্ণ *name)
{
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; extended_handlers[i].handler != রিক্ত; i++) {
		যদি (strcmp(name, extended_handlers[i].ext_name) == 0)
			প্রত্যাগম &extended_handlers[i];
	}
	প্রত্যাগম রিক্ত;
}

স্থির পূর্ণাঙ্ক
request_permitted(ধ্রুব সংরচনা sftp_handler *h)
{
	বর্ণ *result;

	যদি (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		প্রত্যাগম 0;
	}
	যদি (request_denylist != রিক্ত &&
	    ((result = match_list(h->name, request_denylist, রিক্ত))) != রিক্ত) {
		মুক্ত(result);
		verbose("Refusing denylisted %s request", h->name);
		প্রত্যাগম 0;
	}
	যদি (request_allowlist != রিক্ত &&
	    ((result = match_list(h->name, request_allowlist, রিক্ত))) != রিক্ত) {
		মুক্ত(result);
		debug2("Permitting allowlisted %s request", h->name);
		প্রত্যাগম 1;
	}
	যদি (request_allowlist != রিক্ত) {
		verbose("Refusing non-allowlisted %s request", h->name);
		প্রত্যাগম 0;
	}
	প্রত্যাগম 1;
}

স্থির পূর্ণাঙ্ক
errno_to_portable(পূর্ণাঙ্ক unixerrno)
{
	পূর্ণাঙ্ক ret = 0;

	বিকল্প (unixerrno) {
	পক্ষ 0:
		ret = SSH2_FX_OK;
		ভঙ্গ;
	পক্ষ ENOENT:
	পক্ষ ENOTDIR:
	পক্ষ EBADF:
	পক্ষ ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ভঙ্গ;
	পক্ষ EPERM:
	পক্ষ EACCES:
	পক্ষ EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ভঙ্গ;
	পক্ষ ENAMETOOLONG:
	পক্ষ EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		ভঙ্গ;
	পক্ষ ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ভঙ্গ;
	স্বভাব:
		ret = SSH2_FX_FAILURE;
		ভঙ্গ;
	}
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
flags_from_portable(পূর্ণাঙ্ক pflags)
{
	পূর্ণাঙ্ক flags = 0;

	যদি ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} অন্যথা যদি (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} অন্যথা যদি (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	যদি (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	যদি (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	যদি (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	যদি (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	প্রত্যাগম flags;
}

স্থির ধ্রুব বর্ণ *
string_from_portable(পূর্ণাঙ্ক pflags)
{
	স্থির বর্ণ ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		যদি (*ret != '\0')			\
			strlcat(ret, ",", পরিমাণ(ret));	\
		strlcat(ret, str, পরিমাণ(ret));		\
	}

	যদি (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	যদি (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	যদি (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	যদি (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	যদি (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	যদি (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	প্রত্যাগম ret;
}

/* handle handles */

প্রকারনির্দেশ সংরচনা Handle Handle;
সংরচনা Handle {
	পূর্ণাঙ্ক use;
	DIR *dirp;
	পূর্ণাঙ্ক fd;
	পূর্ণাঙ্ক flags;
	বর্ণ *name;
	uint64_t bytes_read, bytes_write;
	পূর্ণাঙ্ক next_unused;
};

গণনা {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

স্থির Handle *handles = রিক্ত;
স্থির u_int অঙ্ক_handles = 0;
স্থির পূর্ণাঙ্ক first_unused_handle = -1;

স্থির শূন্য handle_unused(পূর্ণাঙ্ক i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

স্থির পূর্ণাঙ্ক
handle_new(পূর্ণাঙ্ক use, ধ্রুব বর্ণ *name, পূর্ণাঙ্ক fd, পূর্ণাঙ্ক flags, DIR *dirp)
{
	পূর্ণাঙ্ক i;

	যদি (first_unused_handle == -1) {
		যদি (অঙ্ক_handles + 1 <= অঙ্ক_handles)
			প্রত্যাগম -1;
		অঙ্ক_handles++;
		handles = xreallocarray(handles, অঙ্ক_handles, পরিমাণ(Handle));
		handle_unused(অঙ্ক_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	প্রত্যাগম i;
}

স্থির পূর্ণাঙ্ক
handle_is_ok(পূর্ণাঙ্ক i, পূর্ণাঙ্ক type)
{
	প্রত্যাগম i >= 0 && (u_int)i < অঙ্ক_handles && handles[i].use == type;
}

স্থির পূর্ণাঙ্ক
handle_to_string(পূর্ণাঙ্ক handle, u_char **stringp, পূর্ণাঙ্ক *hlenp)
{
	যদি (stringp == রিক্ত || hlenp == রিক্ত)
		প্রত্যাগম -1;
	*stringp = xmalloc(পরিমাণ(int32_t));
	put_u32(*stringp, handle);
	*hlenp = পরিমাণ(int32_t);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
handle_from_string(ধ্রুব u_char *handle, u_int hlen)
{
	পূর্ণাঙ্ক val;

	যদি (hlen != পরিমাণ(int32_t))
		প্রত্যাগম -1;
	val = get_u32(handle);
	যদি (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		প্রত্যাগম val;
	প্রত্যাগম -1;
}

স্থির বর্ণ *
handle_to_name(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		প্রত্যাগম handles[handle].name;
	প্রত্যাগম রিক্ত;
}

স্থির DIR *
handle_to_dir(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_DIR))
		প্রত্যাগম handles[handle].dirp;
	প্রত্যাগম রিক্ত;
}

স্থির পূর্ণাঙ্ক
handle_to_fd(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_FILE))
		প্রত্যাগম handles[handle].fd;
	প্রত্যাগম -1;
}

স্থির পূর্ণাঙ্ক
handle_to_flags(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_FILE))
		প্রত্যাগম handles[handle].flags;
	প্রত্যাগম 0;
}

স্থির শূন্য
handle_update_read(পূর্ণাঙ্ক handle, ssize_t bytes)
{
	যদি (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

স্থির শূন্য
handle_update_write(পূর্ণাঙ্ক handle, ssize_t bytes)
{
	যদি (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

স্থির uint64_t
handle_bytes_read(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_FILE))
		প্রত্যাগম (handles[handle].bytes_read);
	প্রত্যাগম 0;
}

স্থির uint64_t
handle_bytes_write(পূর্ণাঙ্ক handle)
{
	যদি (handle_is_ok(handle, HANDLE_FILE))
		প্রত্যাগম (handles[handle].bytes_write);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
handle_close(পূর্ণাঙ্ক handle)
{
	পূর্ণাঙ্ক ret = -1;

	যদি (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		মুক্ত(handles[handle].name);
		handle_unused(handle);
	} অন্যথা যদি (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		মুক্ত(handles[handle].name);
		handle_unused(handle);
	} অন্যথা {
		errno = ENOENT;
	}
	প্রত্যাগম ret;
}

স্থির শূন্য
handle_log_close(পূর্ণাঙ্ক handle, বর্ণ *emsg)
{
	যদি (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == রিক্ত ? "" : emsg, emsg == রিক্ত ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} অন্যথা {
		logit("%s%sclosedir \"%s\"",
		    emsg == রিক্ত ? "" : emsg, emsg == রিক্ত ? "" : " ",
		    handle_to_name(handle));
	}
}

স্থির শূন্য
handle_log_exit(শূন্য)
{
	u_int i;

	প্রতি (i = 0; i < অঙ্ক_handles; i++)
		যদি (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

স্থির পূর্ণাঙ্ক
get_handle(সংরচনা sshbuf *queue, পূর্ণাঙ্ক *hp)
{
	u_char *handle;
	পূর্ণাঙ্ক r;
	size_t hlen;

	*hp = -1;
	যদি ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		প্রত্যাগম r;
	যদি (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	মুক্ত(handle);
	প্রত্যাগম 0;
}

/* send replies */

স্থির শূন্য
send_বার্তা(সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

স্থির ধ্রুব বর্ণ *
status_to_message(uint32_t status)
{
	স্থির ধ্রুব বর্ণ * ধ্রুব status_messages[] = {
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
	প্রত্যাগম (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

স্থির শূন্য
send_status_errmsg(uint32_t id, uint32_t status, ধ্রুব বর্ণ *errmsg)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক r;

	debug3("request %u: sent status %u", id, status);
	যদি (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, status)) != 0)
		fatal_fr(r, "compose");
	যদি (version >= 3) {
		যদি ((r = sshbuf_put_cstring(বার্তা, errmsg == রিক্ত ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, রিক্ত);
}

স্থির শূন্য
send_data_or_handle(বর্ণ type, uint32_t id, ধ্রুব u_char *data, পূর্ণাঙ্ক dlen)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক r;

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, type)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
send_data(uint32_t id, ধ্রুব u_char *data, পূর্ণাঙ্ক dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

স্থির শূন্য
send_handle(uint32_t id, পূর্ণাঙ্ক handle)
{
	u_char *string;
	পূর্ণাঙ্ক hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	মুক্ত(string);
}

স্থির শূন্য
send_names(uint32_t id, পূর্ণাঙ্ক গুনতি, ধ্রুব Stat *stats)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক i, r;

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, গুনতি)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, গুনতি);
	প্রতি (i = 0; i < গুনতি; i++) {
		যদি ((r = sshbuf_put_cstring(বার্তা, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(বার্তা, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
send_attrib(uint32_t id, ধ্রুব Attrib *a)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = encode_attrib(বার্তা, a)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
send_statvfs(uint32_t id, সংরচনা statvfs *st)
{
	সংরচনা sshbuf *বার্তা;
	uint64_t flag;
	পূর্ণাঙ্ক r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, flag)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
স্থির পূর্ণাঙ্ক
compose_extension(সংরচনা sshbuf *বার্তা, ধ্রুব বর্ণ *name, ধ্রুব বর্ণ *ver)
{
	পূর্ণাঙ্ক r;
	ধ্রুব সংরচনা sftp_handler *exthnd;

	যদি ((exthnd = extended_handler_byname(name)) == রিক্ত)
		fatal_f("internal error: no handler for %s", name);
	যদি (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		প্রত্যাগম 0;
	}
	যদি ((r = sshbuf_put_cstring(বার্তা, name)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	প্রত্যাগম 0;
}

/* parse incoming */

স্থির শূন্য
process_init(শূন্য)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(বার্তা, "posix-rename@openssh.com", "1");
	compose_extension(বার্তা, "statvfs@openssh.com", "2");
	compose_extension(বার্তা, "fstatvfs@openssh.com", "2");
	compose_extension(বার্তা, "hardlink@openssh.com", "1");
	compose_extension(বার্তা, "fsync@openssh.com", "1");
	compose_extension(বার্তা, "lsetstat@openssh.com", "1");
	compose_extension(বার্তা, "limits@openssh.com", "1");
	compose_extension(বার্তা, "expand-path@openssh.com", "1");
	compose_extension(বার্তা, "copy-data", "1");
	compose_extension(বার্তা, "home-directory", "1");
	compose_extension(বার্তা, "users-groups-by-id@openssh.com", "1");

	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	বর্ণ *name;
	পূর্ণাঙ্ক r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	যদি (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} অন্যথা {
		fd = open(name, flags, mode);
		যদি (fd == -1) {
			status = errno_to_portable(errno);
		} অন্যথা {
			handle = handle_new(HANDLE_FILE, name, fd, flags, রিক্ত);
			যদি (handle < 0) {
				close(fd);
			} অন্যথা {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	যদি (status != SSH2_FX_OK)
		send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_close(uint32_t id)
{
	পূর্ণাঙ্ক r, handle, ret, status = SSH2_FX_FAILURE;

	যদি ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, রিক্ত);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

স্থির শূন্য
process_read(uint32_t id)
{
	স্থির u_char *buf;
	স্থির size_t buflen;
	uint32_t len;
	পূর্ণাঙ্ক r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	যদি ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	যদি ((fd = handle_to_fd(handle)) == -1)
		গচ্ছ out;
	যদি (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	যদি (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		যদি ((buf = realloc(buf, len)) == রিক্ত)
			fatal_f("realloc failed");
		buflen = len;
	}
	যদি (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		গচ্ছ out;
	}
	যদি (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} অন্যথা যদি ((ret = পঠ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		গচ্ছ out;
	} অন্যথা যদি (ret == 0) {
		status = SSH2_FX_EOF;
		গচ্ছ out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	যদি (status != SSH2_FX_OK)
		send_status(id, status);
}

স্থির শূন্য
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	পূর্ণাঙ্ক r, handle, fd, ret, status;
	u_char *data;

	যদি ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	যদি (fd < 0)
		status = SSH2_FX_FAILURE;
	অন্যথা {
		যদি (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} অন্যথা {
/* XXX ATOMICIO ? */
			ret = লিখ(fd, data, len);
			যদি (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} অন্যথা যদি ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} অন্যথা {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	মুক্ত(data);
}

স্থির শূন্য
process_do_stat(uint32_t id, পূর্ণাঙ্ক do_lstat)
{
	Attrib a;
	সংরচনা stat st;
	বর্ণ *name;
	পূর্ণাঙ্ক r, status = SSH2_FX_FAILURE;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	যদি (r == -1) {
		status = errno_to_portable(errno);
	} অন্যথা {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	যদি (status != SSH2_FX_OK)
		send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

স্থির শূন্য
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

স্থির শূন্য
process_fstat(uint32_t id)
{
	Attrib a;
	সংরচনা stat st;
	পূর্ণাঙ্ক fd, r, handle, status = SSH2_FX_FAILURE;

	যদি ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	যদি (fd >= 0) {
		r = fstat(fd, &st);
		যদি (r == -1) {
			status = errno_to_portable(errno);
		} অন্যথা {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	যদি (status != SSH2_FX_OK)
		send_status(id, status);
}

স্থির সংরচনা timeval *
attrib_to_tv(ধ্রুব Attrib *a)
{
	স্থির সংরচনা timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	প্রত্যাগম tv;
}

স্থির সংরচনা timespec *
attrib_to_ts(ধ্রুব Attrib *a)
{
	স্থির সংরচনা timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	প্রত্যাগম ts;
}

স্থির শূন্য
process_setstat(uint32_t id)
{
	Attrib a;
	বর্ণ *name;
	পূর্ণাঙ্ক r, status = SSH2_FX_OK;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	যদি (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		বর্ণ buf[64];
		time_t t = a.mtime;

		strftime(buf, পরিমাণ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_fsetstat(uint32_t id)
{
	Attrib a;
	পূর্ণাঙ্ক handle, fd, r;
	পূর্ণাঙ্ক status = SSH2_FX_OK;

	যদি ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	যদি (fd < 0)
		status = SSH2_FX_FAILURE;
	অন্যথা {
		বর্ণ *name = handle_to_name(handle);

		যদি (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			যদি (r == -1)
				status = errno_to_portable(errno);
		}
		যদি (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#অন্যথা
			r = chmod(name, a.perm & 07777);
#endif
			যদি (r == -1)
				status = errno_to_portable(errno);
		}
		যদি (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			বর্ণ buf[64];
			time_t t = a.mtime;

			strftime(buf, পরিমাণ(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#অন্যথা
			r = utimes(name, attrib_to_tv(&a));
#endif
			যদি (r == -1)
				status = errno_to_portable(errno);
		}
		যদি (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#অন্যথা
			r = chown(name, a.uid, a.gid);
#endif
			যদি (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

স্থির শূন্য
process_opendir(uint32_t id)
{
	DIR *dirp = রিক্ত;
	বর্ণ *path;
	পূর্ণাঙ্ক r, handle, status = SSH2_FX_FAILURE;

	যদি ((r = sshbuf_get_cstring(iqueue, &path, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	যদি (dirp == রিক্ত) {
		status = errno_to_portable(errno);
	} অন্যথা {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		যদি (handle < 0) {
			closedir(dirp);
		} অন্যথা {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	যদি (status != SSH2_FX_OK)
		send_status(id, status);
	মুক্ত(path);
}

স্থির শূন্য
process_readdir(uint32_t id)
{
	DIR *dirp;
	সংরচনা dirent *dp;
	বর্ণ *path;
	পূর্ণাঙ্ক r, handle;

	যদি ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	যদি (dirp == রিক্ত || path == রিক্ত) {
		send_status(id, SSH2_FX_FAILURE);
	} অন্যথা {
		সংরচনা stat st;
		বর্ণ *pathname;
		Stat *stats;
		পূর্ণাঙ্ক nstats = 10, গুনতি = 0, i;

		stats = xcalloc(nstats, পরিমাণ(Stat));
		যাবত্ ((dp = readdir(dirp)) != রিক্ত) {
			যদি (গুনতি >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, পরিমাণ(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			মুক্ত(pathname);
			যদি (r == -1)
				অনুবর্ত;
			stat_to_attrib(&st, &(stats[গুনতি].attrib));
			stats[গুনতি].name = xstrdup(dp->d_name);
			stats[গুনতি].long_name = ls_file(dp->d_name, &st,
			    0, 0, রিক্ত, রিক্ত);
			গুনতি++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			যদি (গুনতি == 100)
				ভঙ্গ;
		}
		যদি (গুনতি > 0) {
			send_names(id, গুনতি, stats);
			প্রতি (i = 0; i < গুনতি; i++) {
				মুক্ত(stats[i].name);
				মুক্ত(stats[i].long_name);
			}
		} অন্যথা {
			send_status(id, SSH2_FX_EOF);
		}
		মুক্ত(stats);
	}
}

স্থির শূন্য
process_remove(uint32_t id)
{
	বর্ণ *name;
	পূর্ণাঙ্ক r, status = SSH2_FX_FAILURE;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_mkdir(uint32_t id)
{
	Attrib a;
	বর্ণ *name;
	পূর্ণাঙ্ক r, mode, status = SSH2_FX_FAILURE;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_rmdir(uint32_t id)
{
	বর্ণ *name;
	পূর্ণাঙ্ক r, status;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_realpath(uint32_t id)
{
	বর্ণ resolvedname[PATH_MAX];
	বর্ণ *path;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_cstring(iqueue, &path, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	যদি (path[0] == '\0') {
		মুক্ত(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	যদি (sftp_realpath(path, resolvedname) == রিক্ত) {
		send_status(id, errno_to_portable(errno));
	} অন্যথা {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	মুক্ত(path);
}

স্থির শূন্য
process_rename(uint32_t id)
{
	বর্ণ *oldpath, *newpath;
	পূর্ণাঙ্ক r, status;
	সংরচনা stat sb;

	যদি ((r = sshbuf_get_cstring(iqueue, &oldpath, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	যদি (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	অন্যথা যদি (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		যদি (link(oldpath, newpath) == -1) {
			যদি (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				সংরচনা stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				যদি (stat(newpath, &st) == -1) {
					যদি (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					অন্যথা
						status = SSH2_FX_OK;
				}
			} অন্যথা {
				status = errno_to_portable(errno);
			}
		} অন্যথা যদি (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} অন্যথা
			status = SSH2_FX_OK;
	} অন্যথা যদি (stat(newpath, &sb) == -1) {
		যদি (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		অন্যথা
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	মুক্ত(oldpath);
	মুক্ত(newpath);
}

স্থির শূন্য
process_readlink(uint32_t id)
{
	পূর্ণাঙ্ক r, len;
	বর্ণ buf[PATH_MAX];
	বর্ণ *path;

	যদি ((r = sshbuf_get_cstring(iqueue, &path, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	যদি ((len = readlink(path, buf, পরিমাণ(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	অন্যথা {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	মুক্ত(path);
}

স্থির শূন্য
process_symlink(uint32_t id)
{
	বর্ণ *oldpath, *newpath;
	পূর্ণাঙ্ক r, status;

	যদি ((r = sshbuf_get_cstring(iqueue, &oldpath, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(oldpath);
	মুক্ত(newpath);
}

স্থির শূন্য
process_extended_posix_rename(uint32_t id)
{
	বর্ণ *oldpath, *newpath;
	পূর্ণাঙ্ক r, status;

	যদি ((r = sshbuf_get_cstring(iqueue, &oldpath, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(oldpath);
	মুক্ত(newpath);
}

স্থির শূন্য
process_extended_statvfs(uint32_t id)
{
	বর্ণ *path;
	সংরচনা statvfs st;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_cstring(iqueue, &path, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	যদি (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	অন্যথা
		send_statvfs(id, &st);
	মুক্ত(path);
}

স্থির শূন্য
process_extended_fstatvfs(uint32_t id)
{
	পূর্ণাঙ্ক r, handle, fd;
	সংরচনা statvfs st;

	যদি ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	যদি ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		প্রত্যাগম;
	}
	যদি (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	অন্যথা
		send_statvfs(id, &st);
}

স্থির শূন্য
process_extended_hardlink(uint32_t id)
{
	বর্ণ *oldpath, *newpath;
	পূর্ণাঙ্ক r, status;

	যদি ((r = sshbuf_get_cstring(iqueue, &oldpath, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	মুক্ত(oldpath);
	মুক্ত(newpath);
}

স্থির শূন্য
process_extended_fsync(uint32_t id)
{
	পূর্ণাঙ্ক handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	যদি ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	যদি ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	অন্যথা যদি (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

স্থির শূন্য
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	বর্ণ *name;
	পূর্ণাঙ্ক r, status = SSH2_FX_OK;

	যদি ((r = sshbuf_get_cstring(iqueue, &name, রিক্ত)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	যদি (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		গচ্ছ out;
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		বর্ণ buf[64];
		time_t t = a.mtime;

		strftime(buf, পরিমাণ(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
	যদি (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		যদি (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	মুক্ত(name);
}

স্থির শূন্য
process_extended_limits(uint32_t id)
{
	সংরচনা sshbuf *বার্তা;
	পূর্ণাঙ্ক r;
	uint64_t nfiles = 0;
#যদি defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	সংরচনা rlimit rlim;
#endif

	debug("request %u: limits", id);

#যদি defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	যদি (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(বার্তা, SFTP_MAX_বার্তা_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(বার্তা, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(বার্তা, SFTP_MAX_বার্তা_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(বার্তা, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(বার্তা);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
process_extended_expand(uint32_t id)
{
	বর্ণ cwd[PATH_MAX], resolvedname[PATH_MAX];
	বর্ণ *path, *npath;
	পূর্ণাঙ্ক r;
	Stat s;

	যদি ((r = sshbuf_get_cstring(iqueue, &path, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	যদি (getcwd(cwd, পরিমাণ(cwd)) == রিক্ত) {
		send_status(id, errno_to_portable(errno));
		গচ্ছ out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	যদি (path[0] == '\0') {
		/* empty path */
		মুক্ত(path);
		path = xstrdup(".");
	} অন্যথা যদি (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		যদি (strcmp(path, "~") == 0) {
			মুক্ত(path);
			path = xstrdup(cwd);
		} অন্যথা যদি (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			মুক্ত(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			মুক্ত(npath);
		} অন্যথা {
			/* ~user expansions */
			যদি (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				গচ্ছ out;
			}
			মুক্ত(path);
			path = npath;
		}
	} অন্যথা যদি (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		মুক্ত(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	যদি (sftp_realpath(path, resolvedname) == রিক্ত) {
		send_status(id, errno_to_portable(errno));
		গচ্ছ out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	মুক্ত(path);
}

স্থির শূন্য
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	পূর্ণাঙ্ক read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	পূর্ণাঙ্ক r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	সংরচনা stat st_read, st_write;

	যদি ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	যদি (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} অন্যথা
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	যদি (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		গচ্ছ out;
	}
	যদি (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		গচ্ছ out;
	}
	যদি (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		গচ্ছ out;
	}
	যদি (read_handle == write_handle ||
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
		গচ্ছ out;
	}

	যদি (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		গচ্ছ out;
	}

	যদি ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		গচ্ছ out;
	}

	/* Process the request in chunks. */
	যাবত্ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(পরিমাণ(buf), read_len);
		read_len -= len;

		ret = atomicio(পঠ, read_fd, buf, len);
		যদি (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ভঙ্গ;
		} অন্যথা যদি (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ভঙ্গ;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		যদি (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			ভঙ্গ;
		}
		handle_update_write(write_handle, len);
	}

	যদি (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

স্থির শূন্য
process_extended_home_directory(uint32_t id)
{
	বর্ণ *username;
	সংরচনা passwd *user_pw;
	পূর্ণাঙ্ক r;
	Stat s;

	যদি ((r = sshbuf_get_cstring(iqueue, &username, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	যদি (username[0] == '\0') {
		user_pw = pw;
	} অন্যথা যদি ((user_pw = getpwnam(username)) == রিক্ত) {
		send_status(id, SSH2_FX_FAILURE);
		গচ্ছ out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	মুক্ত(username);
}

স্থির শূন্য
process_extended_get_users_groups_by_id(uint32_t id)
{
	সংরচনা passwd *user_pw;
	সংরচনা group *gr;
	সংরচনা sshbuf *uids, *gids, *usernames, *groupnames, *বার্তা;
	পূর্ণাঙ্ক r;
	u_int n, nusers = 0, ngroups = 0;
	ধ্রুব বর্ণ *name;

	যদি ((usernames = sshbuf_new()) == রিক্ত ||
	    (groupnames = sshbuf_new()) == রিক্ত ||
	    (বার্তা = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	যাবত্ (sshbuf_len(uids) != 0) {
		যদি ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == রিক্ত ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		যদি ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	যাবত্ (sshbuf_len(gids) != 0) {
		যদি ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == রিক্ত ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		যদি ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(বার্তা);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
process_extended(uint32_t id)
{
	বর্ণ *request;
	পূর্ণাঙ্ক r;
	ধ্রুব সংরচনা sftp_handler *exthand;

	যদি ((r = sshbuf_get_cstring(iqueue, &request, রিক্ত)) != 0)
		fatal_fr(r, "parse");
	যদি ((exthand = extended_handler_byname(request)) == রিক্ত) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} অন্যথা {
		যদি (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		অন্যথা
			exthand->handler(id);
	}
	মুক্ত(request);
}

/* stolen from ssh-agent */

স্থির শূন্য
process(শূন্য)
{
	u_int বার্তা_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ধ্রুব u_char *cp;
	পূর্ণাঙ্ক i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	যদি (buf_len < 5)
		প্রত্যাগম;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	বার্তা_len = get_u32(cp);
	যদি (বার্তা_len > SFTP_MAX_বার্তা_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	যদি (buf_len < বার্তা_len + 4)
		প্রত্যাগম;
	যদি ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	যদি ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	বিকল্প (type) {
	পক্ষ SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		ভঙ্গ;
	পক্ষ SSH2_FXP_EXTENDED:
		যদি (!init_done)
			fatal("Received extended request before init");
		যদি ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ভঙ্গ;
	স্বভাব:
		যদি (!init_done)
			fatal("Received %u request before init", type);
		যদি ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		প্রতি (i = 0; handlers[i].handler != রিক্ত; i++) {
			যদি (type == handlers[i].type) {
				যদি (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} অন্যথা {
					handlers[i].handler(id);
				}
				ভঙ্গ;
			}
		}
		যদি (handlers[i].handler == রিক্ত)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	যদি (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	যদি (বার্তা_len < consumed) {
		error("msg_len %u < consumed %u", বার্তা_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	যদি (বার্তা_len > consumed &&
	    (r = sshbuf_consume(iqueue, বার্তা_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
শূন্য
sftp_server_cleanup_exit(পূর্ণাঙ্ক i)
{
	যদি (pw != রিক্ত && client_addr != রিক্ত) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

স্থির শূন্য
sftp_server_usage(শূন্য)
{
	বাহ্য বর্ণ *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

পূর্ণাঙ্ক
sftp_server_main(পূর্ণাঙ্ক argc, বর্ণ **argv, সংরচনা passwd *user_pw)
{
	পূর্ণাঙ্ক i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	বর্ণ *cp, *homedir = রিক্ত, uidstr[32], buf[4*4096];
	long mask;

	বাহ্য বর্ণ *optarg;
	বাহ্য বর্ণ *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	যাবত্ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'Q':
			যদি (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			প্রতি (i = 0; handlers[i].handler != রিক্ত; i++)
				printf("%s\n", handlers[i].name);
			প্রতি (i = 0; extended_handlers[i].handler != রিক্ত; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			ভঙ্গ;
		পক্ষ 'R':
			readonly = 1;
			ভঙ্গ;
		পক্ষ 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ভঙ্গ;
		পক্ষ 'e':
			log_stderr = 1;
			ভঙ্গ;
		পক্ষ 'l':
			log_level = log_level_সংখ্যা(optarg);
			যদি (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			ভঙ্গ;
		পক্ষ 'f':
			log_facility = log_facility_সংখ্যা(optarg);
			যদি (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			ভঙ্গ;
		পক্ষ 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, পরিমাণ(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (বর্ণ *)রিক্ত);
			মুক্ত(cp);
			ভঙ্গ;
		পক্ষ 'p':
			যদি (request_allowlist != রিক্ত)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ভঙ্গ;
		পক্ষ 'P':
			যদি (request_denylist != রিক্ত)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ভঙ্গ;
		পক্ষ 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			যদি (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(শূন্য)umask((mode_t)mask);
			ভঙ্গ;
		পক্ষ 'h':
		স্বভাব:
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

	যদি ((cp = getenv("SSH_CONNECTION")) != রিক্ত) {
		client_addr = xstrdup(cp);
		যদি ((cp = strchr(client_addr, ' ')) == রিক্ত) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} অন্যথা
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_দ্বিমিক);
	setmode(out, O_দ্বিমিক);
#endif

	যদি ((iqueue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((oqueue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	যদি (homedir != রিক্ত) {
		যদি (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	প্রতি (;;) {
		সংরচনা pollfd pfd[2];

		memset(pfd, 0, পরিমাণ pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		যদি ((r = sshbuf_check_reserve(iqueue, পরিমাণ(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_বার্তা_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		অন্যথা যদি (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		যদি (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		যদি (poll(pfd, 2, -1) == -1) {
			যদি (errno == EINTR)
				অনুবর্ত;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		যদি (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = পঠ(in, buf, পরিমাণ buf);
			যদি (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} অন্যথা যদি (len == -1) {
				যদি (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} অন্যথা যদি ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		যদি (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = লিখ(out, sshbuf_ptr(oqueue), olen);
			যদি (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} অন্যথা যদি (len == -1) {
				sftp_server_cleanup_exit(1);
				যদি (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} অন্যথা যদি ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_বার্তা_LENGTH);
		যদি (r == 0)
			process();
		অন্যথা যদি (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
