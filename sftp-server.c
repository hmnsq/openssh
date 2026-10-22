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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/resource.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/statvfs.h>

#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"

#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"

ଅକ୍ଷର *sftp_realpath(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#define SFTP_MAX_READ_LENGTH (SFTP_MAX_ସନ୍ଦେଶ_LENGTH - 1024)

/* Our verbosity */
ସ୍ଥିର LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
ସ୍ଥିର ସଂରଚନା passwd *pw = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *client_addr = ଖାଲି;

/* input and output queue */
ସଂରଚନା sshbuf *iqueue;
ସଂରଚନା sshbuf *oqueue;

/* Version of client */
ସ୍ଥିର u_int version;

/* SSH2_FXP_INIT received */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା init_done;

/* Disable writes */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା readonly;

/* Requests that are allowed/denied */
ସ୍ଥିର ଅକ୍ଷର *request_allowlist, *request_denylist;

/* portable attributes, etc. */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Stat Stat;

ସଂରଚନା Stat {
	ଅକ୍ଷର *name;
	ଅକ୍ଷର *long_name;
	Attrib attrib;
};

/* Packet handlers */
ସ୍ଥିର ଶୂନ୍ୟ process_open(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_close(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_read(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_write(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_stat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_lstat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_fstat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_setstat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_fsetstat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_opendir(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_readdir(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_remove(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_mkdir(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_rmdir(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_realpath(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_rename(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_readlink(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_symlink(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_posix_rename(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_statvfs(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_fstatvfs(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_hardlink(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_fsync(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_lsetstat(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_limits(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_expand(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_copy_data(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_home_directory(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended_get_users_groups_by_id(uint32_t id);
ସ୍ଥିର ଶୂନ୍ୟ process_extended(uint32_t id);

ସଂରଚନା sftp_handler {
	ଅଚଳ ଅକ୍ଷର *name;	/* user-visible name for fine-grained perms */
	ଅଚଳ ଅକ୍ଷର *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	ଶୂନ୍ୟ (*handler)(uint32_t);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା does_write;		/* if nonzero, banned for readonly mode */
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ଖାଲି, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ଖାଲି, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ଖାଲି, SSH2_FXP_READ, process_read, 0 },
	{ "write", ଖାଲି, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ଖାଲି, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ଖାଲି, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ଖାଲି, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ଖାଲି, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ଖାଲି, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ଖାଲି, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ଖାଲି, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ଖାଲି, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ଖାଲି, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ଖାଲି, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ଖାଲି, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ଖାଲି, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ଖାଲି, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ଖାଲି, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ଖାଲି, ଖାଲି, 0, ଖାଲି, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
ସ୍ଥିର ଅଚଳ ସଂରଚନା sftp_handler extended_handlers[] = {
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
	{ ଖାଲି, ଖାଲି, 0, ଖାଲି, 0 }
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା sftp_handler *
extended_handler_byname(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; extended_handlers[i].handler != ଖାଲି; i++) {
		ଯଦି (strcmp(name, extended_handlers[i].ext_name) == 0)
			ଫେରନ୍ତୁ &extended_handlers[i];
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
request_permitted(ଅଚଳ ସଂରଚନା sftp_handler *h)
{
	ଅକ୍ଷର *result;

	ଯଦି (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (request_denylist != ଖାଲି &&
	    ((result = match_list(h->name, request_denylist, ଖାଲି))) != ଖାଲି) {
		ମୁକ୍ତ(result);
		verbose("Refusing denylisted %s request", h->name);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (request_allowlist != ଖାଲି &&
	    ((result = match_list(h->name, request_allowlist, ଖାଲି))) != ଖାଲି) {
		ମୁକ୍ତ(result);
		debug2("Permitting allowlisted %s request", h->name);
		ଫେରନ୍ତୁ 1;
	}
	ଯଦି (request_allowlist != ଖାଲି) {
		verbose("Refusing non-allowlisted %s request", h->name);
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
errno_to_portable(ପୂର୍ଣ୍ଣସଂଖ୍ୟା unixerrno)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0;

	ବାଛ (unixerrno) {
	ସ୍ଥିତି 0:
		ret = SSH2_FX_OK;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ENOENT:
	ସ୍ଥିତି ENOTDIR:
	ସ୍ଥିତି EBADF:
	ସ୍ଥିତି ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି EPERM:
	ସ୍ଥିତି EACCES:
	ସ୍ଥିତି EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ENAMETOOLONG:
	ସ୍ଥିତି EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ret = SSH2_FX_FAILURE;
		ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
flags_from_portable(ପୂର୍ଣ୍ଣସଂଖ୍ୟା pflags)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags = 0;

	ଯଦି ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} ଅନ୍ୟଥା ଯଦି (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} ଅନ୍ୟଥା ଯଦି (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	ଯଦି (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	ଯଦି (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	ଯଦି (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	ଯଦି (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	ଫେରନ୍ତୁ flags;
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
string_from_portable(ପୂର୍ଣ୍ଣସଂଖ୍ୟା pflags)
{
	ସ୍ଥିର ଅକ୍ଷର ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		ଯଦି (*ret != '\0')			\
			strlcat(ret, ",", ଆକାର(ret));	\
		strlcat(ret, str, ଆକାର(ret));		\
	}

	ଯଦି (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	ଯଦି (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	ଯଦି (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	ଯଦି (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	ଯଦି (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	ଯଦି (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	ଫେରନ୍ତୁ ret;
}

/* handle handles */

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Handle Handle;
ସଂରଚନା Handle {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା use;
	DIR *dirp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags;
	ଅକ୍ଷର *name;
	uint64_t bytes_read, bytes_write;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା next_unused;
};

ଗଣନା {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

ସ୍ଥିର Handle *handles = ଖାଲି;
ସ୍ଥିର u_int ଅଙ୍କ_handles = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା first_unused_handle = -1;

ସ୍ଥିର ଶୂନ୍ୟ handle_unused(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_new(ପୂର୍ଣ୍ଣସଂଖ୍ୟା use, ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, DIR *dirp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (first_unused_handle == -1) {
		ଯଦି (ଅଙ୍କ_handles + 1 <= ଅଙ୍କ_handles)
			ଫେରନ୍ତୁ -1;
		ଅଙ୍କ_handles++;
		handles = xreallocarray(handles, ଅଙ୍କ_handles, ଆକାର(Handle));
		handle_unused(ଅଙ୍କ_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	ଫେରନ୍ତୁ i;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_is_ok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ଫେରନ୍ତୁ i >= 0 && (u_int)i < ଅଙ୍କ_handles && handles[i].use == type;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_to_string(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, u_char **stringp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *hlenp)
{
	ଯଦି (stringp == ଖାଲି || hlenp == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	*stringp = xmalloc(ଆକାର(int32_t));
	put_u32(*stringp, handle);
	*hlenp = ଆକାର(int32_t);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_from_string(ଅଚଳ u_char *handle, u_int hlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	ଯଦି (hlen != ଆକାର(int32_t))
		ଫେରନ୍ତୁ -1;
	val = get_u32(handle);
	ଯଦି (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		ଫେରନ୍ତୁ val;
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ଅକ୍ଷର *
handle_to_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		ଫେରନ୍ତୁ handles[handle].name;
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର DIR *
handle_to_dir(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_DIR))
		ଫେରନ୍ତୁ handles[handle].dirp;
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_to_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE))
		ଫେରନ୍ତୁ handles[handle].fd;
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_to_flags(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE))
		ଫେରନ୍ତୁ handles[handle].flags;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
handle_update_read(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, ssize_t bytes)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

ସ୍ଥିର ଶୂନ୍ୟ
handle_update_write(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, ssize_t bytes)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

ସ୍ଥିର uint64_t
handle_bytes_read(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE))
		ଫେରନ୍ତୁ (handles[handle].bytes_read);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର uint64_t
handle_bytes_write(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE))
		ଫେରନ୍ତୁ (handles[handle].bytes_write);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
handle_close(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		ମୁକ୍ତ(handles[handle].name);
		handle_unused(handle);
	} ଅନ୍ୟଥା ଯଦି (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		ମୁକ୍ତ(handles[handle].name);
		handle_unused(handle);
	} ଅନ୍ୟଥା {
		errno = ENOENT;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
handle_log_close(ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, ଅକ୍ଷର *emsg)
{
	ଯଦି (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ଖାଲି ? "" : emsg, emsg == ଖାଲି ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} ଅନ୍ୟଥା {
		logit("%s%sclosedir \"%s\"",
		    emsg == ଖାଲି ? "" : emsg, emsg == ଖାଲି ? "" : " ",
		    handle_to_name(handle));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
handle_log_exit(ଶୂନ୍ୟ)
{
	u_int i;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_handles; i++)
		ଯଦି (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_handle(ସଂରଚନା sshbuf *queue, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *hp)
{
	u_char *handle;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t hlen;

	*hp = -1;
	ଯଦି ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	ମୁକ୍ତ(handle);
	ଫେରନ୍ତୁ 0;
}

/* send replies */

ସ୍ଥିର ଶୂନ୍ୟ
send_ସନ୍ଦେଶ(ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
status_to_message(uint32_t status)
{
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ status_messages[] = {
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
	ଫେରନ୍ତୁ (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_status_errmsg(uint32_t id, uint32_t status, ଅଚଳ ଅକ୍ଷର *errmsg)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3("request %u: sent status %u", id, status);
	ଯଦି (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, status)) != 0)
		fatal_fr(r, "compose");
	ଯଦି (version >= 3) {
		ଯଦି ((r = sshbuf_put_cstring(ସନ୍ଦେଶ, errmsg == ଖାଲି ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, ଖାଲି);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_data_or_handle(ଅକ୍ଷର type, uint32_t id, ଅଚଳ u_char *data, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dlen)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, type)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, data, dlen)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_data(uint32_t id, ଅଚଳ u_char *data, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_handle(uint32_t id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle)
{
	u_char *string;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	ମୁକ୍ତ(string);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_names(uint32_t id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2, ଅଚଳ Stat *stats)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, ଗଣନା_2)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, ଗଣନା_2);
	ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
		ଯଦି ((r = sshbuf_put_cstring(ସନ୍ଦେଶ, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(ସନ୍ଦେଶ, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_attrib(uint32_t id, ଅଚଳ Attrib *a)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_statvfs(uint32_t id, ସଂରଚନା statvfs *st)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	uint64_t flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, flag)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compose_extension(ସଂରଚନା sshbuf *ସନ୍ଦେଶ, ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ଅକ୍ଷର *ver)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ ସଂରଚନା sftp_handler *exthnd;

	ଯଦି ((exthnd = extended_handler_byname(name)) == ଖାଲି)
		fatal_f("internal error: no handler for %s", name);
	ଯଦି (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((r = sshbuf_put_cstring(ସନ୍ଦେଶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	ଫେରନ୍ତୁ 0;
}

/* parse incoming */

ସ୍ଥିର ଶୂନ୍ୟ
process_init(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(ସନ୍ଦେଶ, "posix-rename@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "statvfs@openssh.com", "2");
	compose_extension(ସନ୍ଦେଶ, "fstatvfs@openssh.com", "2");
	compose_extension(ସନ୍ଦେଶ, "hardlink@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "fsync@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "lsetstat@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "limits@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "expand-path@openssh.com", "1");
	compose_extension(ସନ୍ଦେଶ, "copy-data", "1");
	compose_extension(ସନ୍ଦେଶ, "home-directory", "1");
	compose_extension(ସନ୍ଦେଶ, "users-groups-by-id@openssh.com", "1");

	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	ଯଦି (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} ଅନ୍ୟଥା {
		fd = open(name, flags, mode);
		ଯଦି (fd == -1) {
			status = errno_to_portable(errno);
		} ଅନ୍ୟଥା {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ଖାଲି);
			ଯଦି (handle < 0) {
				close(fd);
			} ଅନ୍ୟଥା {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	ଯଦି (status != SSH2_FX_OK)
		send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_close(uint32_t id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, ret, status = SSH2_FX_FAILURE;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ଖାଲି);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_read(uint32_t id)
{
	ସ୍ଥିର u_char *buf;
	ସ୍ଥିର size_t buflen;
	uint32_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	ଯଦି ((fd = handle_to_fd(handle)) == -1)
		ଯାଅ out;
	ଯଦି (len > SFTP_MAX_READ_LENGTH) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_LENGTH);
		len = SFTP_MAX_READ_LENGTH;
	}
	ଯଦି (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		ଯଦି ((buf = realloc(buf, len)) == ଖାଲି)
			fatal_f("realloc failed");
		buflen = len;
	}
	ଯଦି (lseek(fd, off, SEEK_SET) == -1) {
		status = errno_to_portable(errno);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} ଅନ୍ୟଥା ଯଦି ((ret = ପଠ(fd, buf, len)) == -1) {
		status = errno_to_portable(errno);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    strerror(errno));
		ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (ret == 0) {
		status = SSH2_FX_EOF;
		ଯାଅ out;
	}
	send_data(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	ଯଦି (status != SSH2_FX_OK)
		send_status(id, status);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_write(uint32_t id)
{
	uint64_t off;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, fd, ret, status;
	u_char *data;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	ଯଦି (fd < 0)
		status = SSH2_FX_FAILURE;
	ଅନ୍ୟଥା {
		ଯଦି (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			status = errno_to_portable(errno);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    strerror(errno));
		} ଅନ୍ୟଥା {
/* XXX ATOMICIO ? */
			ret = ଲିଖ(fd, data, len);
			ଯଦି (ret == -1) {
				status = errno_to_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), strerror(errno));
			} ଅନ୍ୟଥା ଯଦି ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} ଅନ୍ୟଥା {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	ମୁକ୍ତ(data);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_do_stat(uint32_t id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_lstat)
{
	Attrib a;
	ସଂରଚନା stat st;
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status = SSH2_FX_FAILURE;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	ଯଦି (r == -1) {
		status = errno_to_portable(errno);
	} ଅନ୍ୟଥା {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	ଯଦି (status != SSH2_FX_OK)
		send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_fstat(uint32_t id)
{
	Attrib a;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, r, handle, status = SSH2_FX_FAILURE;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	ଯଦି (fd >= 0) {
		r = fstat(fd, &st);
		ଯଦି (r == -1) {
			status = errno_to_portable(errno);
		} ଅନ୍ୟଥା {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	ଯଦି (status != SSH2_FX_OK)
		send_status(id, status);
}

ସ୍ଥିର ସଂରଚନା timeval *
attrib_to_tv(ଅଚଳ Attrib *a)
{
	ସ୍ଥିର ସଂରଚନା timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	ଫେରନ୍ତୁ tv;
}

ସ୍ଥିର ସଂରଚନା timespec *
attrib_to_ts(ଅଚଳ Attrib *a)
{
	ସ୍ଥିର ସଂରଚନା timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	ଫେରନ୍ତୁ ts;
}

ସ୍ଥିର ଶୂନ୍ୟ
process_setstat(uint32_t id)
{
	Attrib a;
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status = SSH2_FX_OK;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ଅକ୍ଷର buf[64];
		time_t t = a.mtime;

		strftime(buf, ଆକାର(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_fsetstat(uint32_t id)
{
	Attrib a;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, fd, r;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status = SSH2_FX_OK;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	ଯଦି (fd < 0)
		status = SSH2_FX_FAILURE;
	ଅନ୍ୟଥା {
		ଅକ୍ଷର *name = handle_to_name(handle);

		ଯଦି (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			ଯଦି (r == -1)
				status = errno_to_portable(errno);
		}
		ଯଦି (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#ଅନ୍ୟଥା
			r = chmod(name, a.perm & 07777);
#endif
			ଯଦି (r == -1)
				status = errno_to_portable(errno);
		}
		ଯଦି (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ଅକ୍ଷର buf[64];
			time_t t = a.mtime;

			strftime(buf, ଆକାର(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#ଅନ୍ୟଥା
			r = utimes(name, attrib_to_tv(&a));
#endif
			ଯଦି (r == -1)
				status = errno_to_portable(errno);
		}
		ଯଦି (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#ଅନ୍ୟଥା
			r = chown(name, a.uid, a.gid);
#endif
			ଯଦି (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_opendir(uint32_t id)
{
	DIR *dirp = ଖାଲି;
	ଅକ୍ଷର *path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, status = SSH2_FX_FAILURE;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &path, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	ଯଦି (dirp == ଖାଲି) {
		status = errno_to_portable(errno);
	} ଅନ୍ୟଥା {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		ଯଦି (handle < 0) {
			closedir(dirp);
		} ଅନ୍ୟଥା {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	ଯଦି (status != SSH2_FX_OK)
		send_status(id, status);
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_readdir(uint32_t id)
{
	DIR *dirp;
	ସଂରଚନା dirent *dp;
	ଅକ୍ଷର *path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	ଯଦି (dirp == ଖାଲି || path == ଖାଲି) {
		send_status(id, SSH2_FX_FAILURE);
	} ଅନ୍ୟଥା {
		ସଂରଚନା stat st;
		ଅକ୍ଷର *pathname;
		Stat *stats;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା nstats = 10, ଗଣନା_2 = 0, i;

		stats = xcalloc(nstats, ଆକାର(Stat));
		ଯେତେବେଳେ ((dp = readdir(dirp)) != ଖାଲି) {
			ଯଦି (ଗଣନା_2 >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, ଆକାର(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			ମୁକ୍ତ(pathname);
			ଯଦି (r == -1)
				ଜାରି;
			stat_to_attrib(&st, &(stats[ଗଣନା_2].attrib));
			stats[ଗଣନା_2].name = xstrdup(dp->d_name);
			stats[ଗଣନା_2].long_name = ls_file(dp->d_name, &st,
			    0, 0, ଖାଲି, ଖାଲି);
			ଗଣନା_2++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			ଯଦି (ଗଣନା_2 == 100)
				ଭାଙ୍ଗ;
		}
		ଯଦି (ଗଣନା_2 > 0) {
			send_names(id, ଗଣନା_2, stats);
			ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
				ମୁକ୍ତ(stats[i].name);
				ମୁକ୍ତ(stats[i].long_name);
			}
		} ଅନ୍ୟଥା {
			send_status(id, SSH2_FX_EOF);
		}
		ମୁକ୍ତ(stats);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
process_remove(uint32_t id)
{
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status = SSH2_FX_FAILURE;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_mkdir(uint32_t id)
{
	Attrib a;
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, mode, status = SSH2_FX_FAILURE;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_rmdir(uint32_t id)
{
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_realpath(uint32_t id)
{
	ଅକ୍ଷର resolvedname[PATH_MAX];
	ଅକ୍ଷର *path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &path, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (path[0] == '\0') {
		ମୁକ୍ତ(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	ଯଦି (sftp_realpath(path, resolvedname) == ଖାଲି) {
		send_status(id, errno_to_portable(errno));
	} ଅନ୍ୟଥା {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_rename(uint32_t id)
{
	ଅକ୍ଷର *oldpath, *newpath;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;
	ସଂରଚନା stat sb;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &oldpath, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	ଯଦି (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	ଅନ୍ୟଥା ଯଦି (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		ଯଦି (link(oldpath, newpath) == -1) {
			ଯଦି (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				ସଂରଚନା stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				ଯଦି (stat(newpath, &st) == -1) {
					ଯଦି (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					ଅନ୍ୟଥା
						status = SSH2_FX_OK;
				}
			} ଅନ୍ୟଥା {
				status = errno_to_portable(errno);
			}
		} ଅନ୍ୟଥା ଯଦି (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} ଅନ୍ୟଥା
			status = SSH2_FX_OK;
	} ଅନ୍ୟଥା ଯଦି (stat(newpath, &sb) == -1) {
		ଯଦି (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		ଅନ୍ୟଥା
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	ମୁକ୍ତ(oldpath);
	ମୁକ୍ତ(newpath);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_readlink(uint32_t id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, len;
	ଅକ୍ଷର buf[PATH_MAX];
	ଅକ୍ଷର *path;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &path, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	ଯଦି ((len = readlink(path, buf, ଆକାର(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	ଅନ୍ୟଥା {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_symlink(uint32_t id)
{
	ଅକ୍ଷର *oldpath, *newpath;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &oldpath, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(oldpath);
	ମୁକ୍ତ(newpath);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_posix_rename(uint32_t id)
{
	ଅକ୍ଷର *oldpath, *newpath;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &oldpath, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(oldpath);
	ମୁକ୍ତ(newpath);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_statvfs(uint32_t id)
{
	ଅକ୍ଷର *path;
	ସଂରଚନା statvfs st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &path, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	ଯଦି (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(errno));
	ଅନ୍ୟଥା
		send_statvfs(id, &st);
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_fstatvfs(uint32_t id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, handle, fd;
	ସଂରଚନା statvfs st;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	ଯଦି ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(errno));
	ଅନ୍ୟଥା
		send_statvfs(id, &st);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_hardlink(uint32_t id)
{
	ଅକ୍ଷର *oldpath, *newpath;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &oldpath, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	ମୁକ୍ତ(oldpath);
	ମୁକ୍ତ(newpath);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_fsync(uint32_t id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	ଯଦି ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	ଯଦି ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	ଅନ୍ୟଥା ଯଦି (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	ଅକ୍ଷର *name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, status = SSH2_FX_OK;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &name, ଖାଲି)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		ଯାଅ out;
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ଅକ୍ଷର buf[64];
		time_t t = a.mtime;

		strftime(buf, ଆକାର(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
	ଯଦି (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		ଯଦି (r == -1)
			status = errno_to_portable(errno);
	}
 out:
	send_status(id, status);
	ମୁକ୍ତ(name);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_limits(uint32_t id)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	uint64_t nfiles = 0;
#ଯଦି defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ସଂରଚନା rlimit rlim;
#endif

	debug("request %u: limits", id);

#ଯଦି defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ଯଦି (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#endif

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, SFTP_MAX_ସନ୍ଦେଶ_LENGTH)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, SFTP_MAX_READ_LENGTH)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, SFTP_MAX_ସନ୍ଦେଶ_LENGTH - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_expand(uint32_t id)
{
	ଅକ୍ଷର cwd[PATH_MAX], resolvedname[PATH_MAX];
	ଅକ୍ଷର *path, *npath;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	Stat s;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &path, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (getcwd(cwd, ଆକାର(cwd)) == ଖାଲି) {
		send_status(id, errno_to_portable(errno));
		ଯାଅ out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	ଯଦି (path[0] == '\0') {
		/* empty path */
		ମୁକ୍ତ(path);
		path = xstrdup(".");
	} ଅନ୍ୟଥା ଯଦି (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		ଯଦି (strcmp(path, "~") == 0) {
			ମୁକ୍ତ(path);
			path = xstrdup(cwd);
		} ଅନ୍ୟଥା ଯଦି (strncmp(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			ମୁକ୍ତ(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			ମୁକ୍ତ(npath);
		} ଅନ୍ୟଥା {
			/* ~user expansions */
			ଯଦି (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				ଯାଅ out;
			}
			ମୁକ୍ତ(path);
			path = npath;
		}
	} ଅନ୍ୟଥା ଯଦି (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		ମୁକ୍ତ(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	ଯଦି (sftp_realpath(path, resolvedname) == ଖାଲି) {
		send_status(id, errno_to_portable(errno));
		ଯାଅ out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_copy_data(uint32_t id)
{
	u_char buf[64*1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	size_t ret;
	ସଂରଚନା stat st_read, st_write;

	ଯଦି ((r = get_handle(iqueue, &read_handle)) != 0 ||
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
	ଯଦି (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} ଅନ୍ୟଥା
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	ଯଦି (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		ଯାଅ out;
	}
	ଯଦି (fstat(read_fd, &st_read) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (fstat(write_fd, &st_write) != 0) {
		status = errno_to_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		ଯାଅ out;
	}
	ଯଦି (read_handle == write_handle ||
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
		ଯାଅ out;
	}

	ଯଦି (lseek(read_fd, read_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("read_seek failed");
		ଯାଅ out;
	}

	ଯଦି ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		status = errno_to_portable(errno);
		error_f("write_seek failed");
		ଯାଅ out;
	}

	/* Process the request in chunks. */
	ଯେତେବେଳେ (read_len > 0 || copy_until_eof) {
		len = MINIMUM(ଆକାର(buf), read_len);
		read_len -= len;

		ret = atomicio(ପଠ, read_fd, buf, len);
		ଯଦି (ret == 0 && errno == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ଭାଙ୍ଗ;
		} ଅନ୍ୟଥା ଯଦି (ret == 0) {
			status = errno_to_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ଭାଙ୍ଗ;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		ଯଦି (ret != len) {
			status = errno_to_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (unsigned long long)ret, (unsigned long long)len,
			    strerror(errno));
			ଭାଙ୍ଗ;
		}
		handle_update_write(write_handle, len);
	}

	ଯଦି (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_home_directory(uint32_t id)
{
	ଅକ୍ଷର *username;
	ସଂରଚନା passwd *user_pw;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	Stat s;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &username, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	ଯଦି (username[0] == '\0') {
		user_pw = pw;
	} ଅନ୍ୟଥା ଯଦି ((user_pw = getpwnam(username)) == ଖାଲି) {
		send_status(id, SSH2_FX_FAILURE);
		ଯାଅ out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	ମୁକ୍ତ(username);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended_get_users_groups_by_id(uint32_t id)
{
	ସଂରଚନା passwd *user_pw;
	ସଂରଚନା group *gr;
	ସଂରଚନା sshbuf *uids, *gids, *usernames, *groupnames, *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int n, nusers = 0, ngroups = 0;
	ଅଚଳ ଅକ୍ଷର *name;

	ଯଦି ((usernames = sshbuf_new()) == ଖାଲି ||
	    (groupnames = sshbuf_new()) == ଖାଲି ||
	    (ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	ଯେତେବେଳେ (sshbuf_len(uids) != 0) {
		ଯଦି ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ଖାଲି ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		ଯଦି ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	ଯେତେବେଳେ (sshbuf_len(gids) != 0) {
		ଯଦି ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ଖାଲି ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		ଯଦି ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(ସନ୍ଦେଶ);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
process_extended(uint32_t id)
{
	ଅକ୍ଷର *request;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ ସଂରଚନା sftp_handler *exthand;

	ଯଦି ((r = sshbuf_get_cstring(iqueue, &request, ଖାଲି)) != 0)
		fatal_fr(r, "parse");
	ଯଦି ((exthand = extended_handler_byname(request)) == ଖାଲି) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} ଅନ୍ୟଥା {
		ଯଦି (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		ଅନ୍ୟଥା
			exthand->handler(id);
	}
	ମୁକ୍ତ(request);
}

/* stolen from ssh-agent */

ସ୍ଥିର ଶୂନ୍ୟ
process(ଶୂନ୍ୟ)
{
	u_int ସନ୍ଦେଶ_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ଅଚଳ u_char *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	ଯଦି (buf_len < 5)
		ଫେରନ୍ତୁ;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	ସନ୍ଦେଶ_len = get_u32(cp);
	ଯଦି (ସନ୍ଦେଶ_len > SFTP_MAX_ସନ୍ଦେଶ_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	ଯଦି (buf_len < ସନ୍ଦେଶ_len + 4)
		ଫେରନ୍ତୁ;
	ଯଦି ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	ଯଦି ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	ବାଛ (type) {
	ସ୍ଥିତି SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH2_FXP_EXTENDED:
		ଯଦି (!init_done)
			fatal("Received extended request before init");
		ଯଦି ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଯଦି (!init_done)
			fatal("Received %u request before init", type);
		ଯଦି ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		ପାଇଁ (i = 0; handlers[i].handler != ଖାଲି; i++) {
			ଯଦି (type == handlers[i].type) {
				ଯଦି (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} ଅନ୍ୟଥା {
					handlers[i].handler(id);
				}
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (handlers[i].handler == ଖାଲି)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	ଯଦି (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ଯଦି (ସନ୍ଦେଶ_len < consumed) {
		error("msg_len %u < consumed %u", ସନ୍ଦେଶ_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	ଯଦି (ସନ୍ଦେଶ_len > consumed &&
	    (r = sshbuf_consume(iqueue, ସନ୍ଦେଶ_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
ଶୂନ୍ୟ
sftp_server_cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	ଯଦି (pw != ଖାଲି && client_addr != ଖାଲି) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

ସ୍ଥିର ଶୂନ୍ୟ
sftp_server_usage(ଶୂନ୍ୟ)
{
	ବାହ୍ୟ ଅକ୍ଷର *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_server_main(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ସଂରଚନା passwd *user_pw)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	ଅକ୍ଷର *cp, *homedir = ଖାଲି, uidstr[32], buf[4*4096];
	long mask;

	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ଅକ୍ଷର *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	ଯେତେବେଳେ (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'Q':
			ଯଦି (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			ପାଇଁ (i = 0; handlers[i].handler != ଖାଲି; i++)
				printf("%s\n", handlers[i].name);
			ପାଇଁ (i = 0; extended_handlers[i].handler != ଖାଲି; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			readonly = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'e':
			log_stderr = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			log_level = log_level_ସଂଖ୍ୟା(optarg);
			ଯଦି (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			log_facility = log_facility_ସଂଖ୍ୟା(optarg);
			ଯଦି (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, ଆକାର(uidstr), "%llu",
			    (unsigned long long)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (ଅକ୍ଷର *)ଖାଲି);
			ମୁକ୍ତ(cp);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			ଯଦି (request_allowlist != ଖାଲି)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			ଯଦି (request_denylist != ଖାଲି)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			ଯଦି (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(ଶୂନ୍ୟ)umask((mode_t)mask);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
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

	ଯଦି ((cp = getenv("SSH_CONNECTION")) != ଖାଲି) {
		client_addr = xstrdup(cp);
		ଯଦି ((cp = strchr(client_addr, ' ')) == ଖାଲି) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} ଅନ୍ୟଥା
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_ଦ୍ୱିମିକ);
	setmode(out, O_ଦ୍ୱିମିକ);
#endif

	ଯଦି ((iqueue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((oqueue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯଦି (homedir != ଖାଲି) {
		ଯଦି (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	ପାଇଁ (;;) {
		ସଂରଚନା pollfd pfd[2];

		memset(pfd, 0, ଆକାର pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ଯଦି ((r = sshbuf_check_reserve(iqueue, ଆକାର(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_ସନ୍ଦେଶ_LENGTH)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		ଯଦି (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		ଯଦି (poll(pfd, 2, -1) == -1) {
			ଯଦି (errno == EINTR)
				ଜାରି;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		ଯଦି (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = ପଠ(in, buf, ଆକାର buf);
			ଯଦି (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} ଅନ୍ୟଥା ଯଦି (len == -1) {
				ଯଦି (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ଯଦି (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ଲିଖ(out, sshbuf_ptr(oqueue), olen);
			ଯଦି (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} ଅନ୍ୟଥା ଯଦି (len == -1) {
				sftp_server_cleanup_exit(1);
				ଯଦି (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_ସନ୍ଦେଶ_LENGTH);
		ଯଦି (r == 0)
			process();
		ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");
	}
}
