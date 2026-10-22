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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/resource.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/statvfs.h>

#అన్తర్భావ <dirent.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <grp.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "uidswap.h"

#అన్తర్భావ "sftp.h"
#అన్తర్భావ "sftp-common.h"

అక్షరం *sftp_realpath(స్థిరరాశి అక్షరం *, అక్షరం *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#నిర్వచించు SFTP_MAX_READ_నిడివి (SFTP_MAX_సందేశం_నిడివి - 1024)

/* Our verbosity */
స్థిర LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
స్థిర నిర్మాణం passwd *pw = ఖాళీ;
స్థిర అక్షరం *client_addr = ఖాళీ;

/* input and output queue */
నిర్మాణం sshbuf *iqueue;
నిర్మాణం sshbuf *oqueue;

/* Version of client */
స్థిర u_int సంస్కరణ;

/* SSH2_FXP_INIT received */
స్థిర పూర్ణాంకం init_పూర్తి;

/* Disable writes */
స్థిర పూర్ణాంకం readonly;

/* Requests that are allowed/denied */
స్థిర అక్షరం *request_allowlist, *request_denylist;

/* portable attributes, etc. */
రకనిర్వచనం నిర్మాణం Stat Stat;

నిర్మాణం Stat {
	అక్షరం *name;
	అక్షరం *long_name;
	Attrib attrib;
};

/* Packet handlers */
స్థిర శూన్య process_open(uint32_t id);
స్థిర శూన్య process_close(uint32_t id);
స్థిర శూన్య process_read(uint32_t id);
స్థిర శూన్య process_write(uint32_t id);
స్థిర శూన్య process_stat(uint32_t id);
స్థిర శూన్య process_lstat(uint32_t id);
స్థిర శూన్య process_fstat(uint32_t id);
స్థిర శూన్య process_setstat(uint32_t id);
స్థిర శూన్య process_fsetstat(uint32_t id);
స్థిర శూన్య process_opendir(uint32_t id);
స్థిర శూన్య process_readdir(uint32_t id);
స్థిర శూన్య process_remove(uint32_t id);
స్థిర శూన్య process_mkdir(uint32_t id);
స్థిర శూన్య process_rmdir(uint32_t id);
స్థిర శూన్య process_realpath(uint32_t id);
స్థిర శూన్య process_rename(uint32_t id);
స్థిర శూన్య process_readlink(uint32_t id);
స్థిర శూన్య process_symlink(uint32_t id);
స్థిర శూన్య process_extended_posix_rename(uint32_t id);
స్థిర శూన్య process_extended_statvfs(uint32_t id);
స్థిర శూన్య process_extended_fstatvfs(uint32_t id);
స్థిర శూన్య process_extended_hardlink(uint32_t id);
స్థిర శూన్య process_extended_fsync(uint32_t id);
స్థిర శూన్య process_extended_lsetstat(uint32_t id);
స్థిర శూన్య process_extended_limits(uint32_t id);
స్థిర శూన్య process_extended_expand(uint32_t id);
స్థిర శూన్య process_extended_copy_దత్తాంశం(uint32_t id);
స్థిర శూన్య process_extended_home_directory(uint32_t id);
స్థిర శూన్య process_extended_get_users_groups_by_id(uint32_t id);
స్థిర శూన్య process_extended(uint32_t id);

నిర్మాణం sftp_handler {
	స్థిరరాశి అక్షరం *name;	/* user-visible name for fine-grained perms */
	స్థిరరాశి అక్షరం *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	శూన్య (*handler)(uint32_t);
	పూర్ణాంకం does_write;		/* if nonzero, banned for readonly mode */
};

స్థిర స్థిరరాశి నిర్మాణం sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", ఖాళీ, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", ఖాళీ, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", ఖాళీ, SSH2_FXP_READ, process_read, 0 },
	{ "write", ఖాళీ, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", ఖాళీ, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", ఖాళీ, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", ఖాళీ, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", ఖాళీ, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", ఖాళీ, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", ఖాళీ, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", ఖాళీ, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", ఖాళీ, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", ఖాళీ, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", ఖాళీ, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", ఖాళీ, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", ఖాళీ, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", ఖాళీ, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", ఖాళీ, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ ఖాళీ, ఖాళీ, 0, ఖాళీ, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
స్థిర స్థిరరాశి నిర్మాణం sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_దత్తాంశం, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ ఖాళీ, ఖాళీ, 0, ఖాళీ, 0 }
};

స్థిర స్థిరరాశి నిర్మాణం sftp_handler *
extended_handler_byname(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; extended_handlers[i].handler != ఖాళీ; i++) {
		ఒకవేళ (strcmp(name, extended_handlers[i].ext_name) == 0)
			తిరిగి &extended_handlers[i];
	}
	తిరిగి ఖాళీ;
}

స్థిర పూర్ణాంకం
request_permitted(స్థిరరాశి నిర్మాణం sftp_handler *h)
{
	అక్షరం *ఫలితం;

	ఒకవేళ (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		తిరిగి 0;
	}
	ఒకవేళ (request_denylist != ఖాళీ &&
	    ((ఫలితం = సరిపోలిక_list(h->name, request_denylist, ఖాళీ))) != ఖాళీ) {
		విడుదల(ఫలితం);
		verbose("Refusing denylisted %s request", h->name);
		తిరిగి 0;
	}
	ఒకవేళ (request_allowlist != ఖాళీ &&
	    ((ఫలితం = సరిపోలిక_list(h->name, request_allowlist, ఖాళీ))) != ఖాళీ) {
		విడుదల(ఫలితం);
		debug2("Permitting allowlisted %s request", h->name);
		తిరిగి 1;
	}
	ఒకవేళ (request_allowlist != ఖాళీ) {
		verbose("Refusing non-allowlisted %s request", h->name);
		తిరిగి 0;
	}
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
errno_గమ్యం_portable(పూర్ణాంకం unixerrno)
{
	పూర్ణాంకం ret = 0;

	ఎంపిక (unixerrno) {
	స్థితి 0:
		ret = SSH2_FX_OK;
		ఆపు;
	స్థితి ENOENT:
	స్థితి ENOTDIR:
	స్థితి EBADF:
	స్థితి ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		ఆపు;
	స్థితి EPERM:
	స్థితి EACCES:
	స్థితి EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		ఆపు;
	స్థితి ENAMETOOLONG:
	స్థితి EINVAL:
		ret = SSH2_FX_BAD_సందేశం;
		ఆపు;
	స్థితి ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		ఆపు;
	అప్రమేయ:
		ret = SSH2_FX_FAILURE;
		ఆపు;
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
flags_from_portable(పూర్ణాంకం pflags)
{
	పూర్ణాంకం flags = 0;

	ఒకవేళ ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} లేకపోతే ఒకవేళ (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} లేకపోతే ఒకవేళ (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	ఒకవేళ (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	ఒకవేళ (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	ఒకవేళ (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	ఒకవేళ (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	తిరిగి flags;
}

స్థిర స్థిరరాశి అక్షరం *
string_from_portable(పూర్ణాంకం pflags)
{
	స్థిర అక్షరం ret[128];

	*ret = '\0';

#నిర్వచించు PAPPEND(str)	{				\
		ఒకవేళ (*ret != '\0')			\
			strlcat(ret, ",", పరిమాణం(ret));	\
		strlcat(ret, str, పరిమాణం(ret));		\
	}

	ఒకవేళ (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	ఒకవేళ (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	ఒకవేళ (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	ఒకవేళ (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	ఒకవేళ (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	ఒకవేళ (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	తిరిగి ret;
}

/* handle handles */

రకనిర్వచనం నిర్మాణం Handle Handle;
నిర్మాణం Handle {
	పూర్ణాంకం use;
	DIR *dirp;
	పూర్ణాంకం fd;
	పూర్ణాంకం flags;
	అక్షరం *name;
	uint64_t బైట్లు_read, బైట్లు_write;
	పూర్ణాంకం తదుపరి_వాడని;
};

గణన {
	HANDLE_వాడని,
	HANDLE_DIR,
	HANDLE_FILE
};

స్థిర Handle *handles = ఖాళీ;
స్థిర u_int అంకె_handles = 0;
స్థిర పూర్ణాంకం మొదటి_వాడని_handle = -1;

స్థిర శూన్య handle_వాడని(పూర్ణాంకం i)
{
	handles[i].use = HANDLE_వాడని;
	handles[i].తదుపరి_వాడని = మొదటి_వాడని_handle;
	మొదటి_వాడని_handle = i;
}

స్థిర పూర్ణాంకం
handle_new(పూర్ణాంకం use, స్థిరరాశి అక్షరం *name, పూర్ణాంకం fd, పూర్ణాంకం flags, DIR *dirp)
{
	పూర్ణాంకం i;

	ఒకవేళ (మొదటి_వాడని_handle == -1) {
		ఒకవేళ (అంకె_handles + 1 <= అంకె_handles)
			తిరిగి -1;
		అంకె_handles++;
		handles = xreallocarray(handles, అంకె_handles, పరిమాణం(Handle));
		handle_వాడని(అంకె_handles - 1);
	}

	i = మొదటి_వాడని_handle;
	మొదటి_వాడని_handle = handles[i].తదుపరి_వాడని;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].బైట్లు_read = handles[i].బైట్లు_write = 0;

	తిరిగి i;
}

స్థిర పూర్ణాంకం
handle_is_ok(పూర్ణాంకం i, పూర్ణాంకం type)
{
	తిరిగి i >= 0 && (u_int)i < అంకె_handles && handles[i].use == type;
}

స్థిర పూర్ణాంకం
handle_గమ్యం_string(పూర్ణాంకం handle, u_char **stringp, పూర్ణాంకం *hlenp)
{
	ఒకవేళ (stringp == ఖాళీ || hlenp == ఖాళీ)
		తిరిగి -1;
	*stringp = xmalloc(పరిమాణం(int32_t));
	put_u32(*stringp, handle);
	*hlenp = పరిమాణం(int32_t);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
handle_from_string(స్థిరరాశి u_char *handle, u_int hlen)
{
	పూర్ణాంకం val;

	ఒకవేళ (hlen != పరిమాణం(int32_t))
		తిరిగి -1;
	val = get_u32(handle);
	ఒకవేళ (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		తిరిగి val;
	తిరిగి -1;
}

స్థిర అక్షరం *
handle_గమ్యం_name(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		తిరిగి handles[handle].name;
	తిరిగి ఖాళీ;
}

స్థిర DIR *
handle_గమ్యం_dir(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_DIR))
		తిరిగి handles[handle].dirp;
	తిరిగి ఖాళీ;
}

స్థిర పూర్ణాంకం
handle_గమ్యం_fd(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE))
		తిరిగి handles[handle].fd;
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
handle_గమ్యం_flags(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE))
		తిరిగి handles[handle].flags;
	తిరిగి 0;
}

స్థిర శూన్య
handle_update_read(పూర్ణాంకం handle, ssize_t బైట్లు)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE) && బైట్లు > 0)
		handles[handle].బైట్లు_read += బైట్లు;
}

స్థిర శూన్య
handle_update_write(పూర్ణాంకం handle, ssize_t బైట్లు)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE) && బైట్లు > 0)
		handles[handle].బైట్లు_write += బైట్లు;
}

స్థిర uint64_t
handle_బైట్లు_read(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE))
		తిరిగి (handles[handle].బైట్లు_read);
	తిరిగి 0;
}

స్థిర uint64_t
handle_బైట్లు_write(పూర్ణాంకం handle)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE))
		తిరిగి (handles[handle].బైట్లు_write);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
handle_close(పూర్ణాంకం handle)
{
	పూర్ణాంకం ret = -1;

	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		విడుదల(handles[handle].name);
		handle_వాడని(handle);
	} లేకపోతే ఒకవేళ (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		విడుదల(handles[handle].name);
		handle_వాడని(handle);
	} లేకపోతే {
		errno = ENOENT;
	}
	తిరిగి ret;
}

స్థిర శూన్య
handle_log_close(పూర్ణాంకం handle, అక్షరం *emsg)
{
	ఒకవేళ (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == ఖాళీ ? "" : emsg, emsg == ఖాళీ ? "" : " ",
		    handle_గమ్యం_name(handle),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)handle_బైట్లు_read(handle),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)handle_బైట్లు_write(handle));
	} లేకపోతే {
		logit("%s%sclosedir \"%s\"",
		    emsg == ఖాళీ ? "" : emsg, emsg == ఖాళీ ? "" : " ",
		    handle_గమ్యం_name(handle));
	}
}

స్థిర శూన్య
handle_log_exit(శూన్య)
{
	u_int i;

	కొరకు (i = 0; i < అంకె_handles; i++)
		ఒకవేళ (handles[i].use != HANDLE_వాడని)
			handle_log_close(i, "forced");
}

స్థిర పూర్ణాంకం
get_handle(నిర్మాణం sshbuf *వరుస, పూర్ణాంకం *hp)
{
	u_char *handle;
	పూర్ణాంకం r;
	కొలత_t hlen;

	*hp = -1;
	ఒకవేళ ((r = sshbuf_get_string(వరుస, &handle, &hlen)) != 0)
		తిరిగి r;
	ఒకవేళ (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	విడుదల(handle);
	తిరిగి 0;
}

/* send replies */

స్థిర శూన్య
send_సందేశం(నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

స్థిర స్థిరరాశి అక్షరం *
స్థితి_గమ్యం_సందేశం(uint32_t స్థితి_2)
{
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి స్థితి_messages[] = {
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
	తిరిగి (స్థితి_messages[MINIMUM(స్థితి_2,SSH2_FX_MAX)]);
}

స్థిర శూన్య
send_స్థితి_errmsg(uint32_t id, uint32_t స్థితి_2, స్థిరరాశి అక్షరం *errmsg)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	debug3("request %u: sent status %u", id, స్థితి_2);
	ఒకవేళ (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (స్థితి_2 != SSH2_FX_OK && స్థితి_2 != SSH2_FX_EOF))
		logit("sent status %s", స్థితి_గమ్యం_సందేశం(స్థితి_2));
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_స్థితి)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, స్థితి_2)) != 0)
		fatal_fr(r, "compose");
	ఒకవేళ (సంస్కరణ >= 3) {
		ఒకవేళ ((r = sshbuf_put_cstring(సందేశం, errmsg == ఖాళీ ?
		    స్థితి_గమ్యం_సందేశం(స్థితి_2) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
send_స్థితి(uint32_t id, uint32_t స్థితి_2)
{
	send_స్థితి_errmsg(id, స్థితి_2, ఖాళీ);
}

స్థిర శూన్య
send_దత్తాంశం_or_handle(అక్షరం type, uint32_t id, స్థిరరాశి u_char *దత్తాంశం, పూర్ణాంకం dlen)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, type)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, దత్తాంశం, dlen)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
send_దత్తాంశం(uint32_t id, స్థిరరాశి u_char *దత్తాంశం, పూర్ణాంకం dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_దత్తాంశం_or_handle(SSH2_FXP_దత్తాంశం, id, దత్తాంశం, dlen);
}

స్థిర శూన్య
send_handle(uint32_t id, పూర్ణాంకం handle)
{
	u_char *string;
	పూర్ణాంకం hlen;

	handle_గమ్యం_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_దత్తాంశం_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	విడుదల(string);
}

స్థిర శూన్య
send_పేర్లు(uint32_t id, పూర్ణాంకం లెక్క, స్థిరరాశి Stat *stats)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం i, r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, లెక్క)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, లెక్క);
	కొరకు (i = 0; i < లెక్క; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(సందేశం, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(సందేశం, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
send_attrib(uint32_t id, స్థిరరాశి Attrib *a)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = encode_attrib(సందేశం, a)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
send_statvfs(uint32_t id, నిర్మాణం statvfs *st)
{
	నిర్మాణం sshbuf *సందేశం;
	uint64_t flag;
	పూర్ణాంకం r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED_జవాబు)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_ఖండాలు)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, FSID_గమ్యం_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, flag)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
స్థిర పూర్ణాంకం
compose_extension(నిర్మాణం sshbuf *సందేశం, స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *ver)
{
	పూర్ణాంకం r;
	స్థిరరాశి నిర్మాణం sftp_handler *exthnd;

	ఒకవేళ ((exthnd = extended_handler_byname(name)) == ఖాళీ)
		fatal_f("internal error: no handler for %s", name);
	ఒకవేళ (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		తిరిగి 0;
	}
	ఒకవేళ ((r = sshbuf_put_cstring(సందేశం, name)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	తిరిగి 0;
}

/* parse incoming */

స్థిర శూన్య
process_init(శూన్య)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_u32(iqueue, &సంస్కరణ)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", సంస్కరణ);
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, SSH2_FILEXFER_సంస్కరణ)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(సందేశం, "posix-rename@openssh.com", "1");
	compose_extension(సందేశం, "statvfs@openssh.com", "2");
	compose_extension(సందేశం, "fstatvfs@openssh.com", "2");
	compose_extension(సందేశం, "hardlink@openssh.com", "1");
	compose_extension(సందేశం, "fsync@openssh.com", "1");
	compose_extension(సందేశం, "lsetstat@openssh.com", "1");
	compose_extension(సందేశం, "limits@openssh.com", "1");
	compose_extension(సందేశం, "expand-path@openssh.com", "1");
	compose_extension(సందేశం, "copy-data", "1");
	compose_extension(సందేశం, "home-directory", "1");
	compose_extension(సందేశం, "users-groups-by-id@openssh.com", "1");

	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	అక్షరం *name;
	పూర్ణాంకం r, handle, fd, flags, బహుళకం, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	బహుళకం = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), బహుళకం);
	ఒకవేళ (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		స్థితి_2 = SSH2_FX_PERMISSION_DENIED;
	} లేకపోతే {
		fd = open(name, flags, బహుళకం);
		ఒకవేళ (fd == -1) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
		} లేకపోతే {
			handle = handle_new(HANDLE_FILE, name, fd, flags, ఖాళీ);
			ఒకవేళ (handle < 0) {
				close(fd);
			} లేకపోతే {
				send_handle(id, handle);
				స్థితి_2 = SSH2_FX_OK;
			}
		}
	}
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_close(uint32_t id)
{
	పూర్ణాంకం r, handle, ret, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, ఖాళీ);
	ret = handle_close(handle);
	స్థితి_2 = (ret == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
}

స్థిర శూన్య
process_read(uint32_t id)
{
	స్థిర u_char *buf;
	స్థిర కొలత_t buflen;
	uint32_t len;
	పూర్ణాంకం r, handle, fd, ret, స్థితి_2 = SSH2_FX_FAILURE;
	uint64_t off;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_గమ్యం_name(handle), handle, (గుర్తులేని దీర్ఘ దీర్ఘ)off, len);
	ఒకవేళ ((fd = handle_గమ్యం_fd(handle)) == -1)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (len > SFTP_MAX_READ_నిడివి) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_నిడివి);
		len = SFTP_MAX_READ_నిడివి;
	}
	ఒకవేళ (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		ఒకవేళ ((buf = realloc(buf, len)) == ఖాళీ)
			fatal_f("realloc failed");
		buflen = len;
	}
	ఒకవేళ (lseek(fd, off, SEEK_SET) == -1) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("seek \"%.100s\": %s", handle_గమ్యం_name(handle),
		    strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} లేకపోతే ఒకవేళ ((ret = పఠ(fd, buf, len)) == -1) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("read \"%.100s\": %s", handle_గమ్యం_name(handle),
		    strerror(errno));
		వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (ret == 0) {
		స్థితి_2 = SSH2_FX_EOF;
		వెళ్ళు బహిర్గతం;
	}
	send_దత్తాంశం(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	స్థితి_2 = SSH2_FX_OK;
 బహిర్గతం:
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		send_స్థితి(id, స్థితి_2);
}

స్థిర శూన్య
process_write(uint32_t id)
{
	uint64_t off;
	కొలత_t len;
	పూర్ణాంకం r, handle, fd, ret, స్థితి_2;
	u_char *దత్తాంశం;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &దత్తాంశం, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_గమ్యం_name(handle), handle, (గుర్తులేని దీర్ఘ దీర్ఘ)off, len);
	fd = handle_గమ్యం_fd(handle);

	ఒకవేళ (fd < 0)
		స్థితి_2 = SSH2_FX_FAILURE;
	లేకపోతే {
		ఒకవేళ (!(handle_గమ్యం_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
			error_f("seek \"%.100s\": %s", handle_గమ్యం_name(handle),
			    strerror(errno));
		} లేకపోతే {
/* XXX ATOMICIO ? */
			ret = లిఖ(fd, దత్తాంశం, len);
			ఒకవేళ (ret == -1) {
				స్థితి_2 = errno_గమ్యం_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_గమ్యం_name(handle), strerror(errno));
			} లేకపోతే ఒకవేళ ((కొలత_t)ret == len) {
				స్థితి_2 = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} లేకపోతే {
				debug2_f("nothing at all written");
				స్థితి_2 = SSH2_FX_FAILURE;
			}
		}
	}
	send_స్థితి(id, స్థితి_2);
	విడుదల(దత్తాంశం);
}

స్థిర శూన్య
process_do_stat(uint32_t id, పూర్ణాంకం do_lstat)
{
	Attrib a;
	నిర్మాణం stat st;
	అక్షరం *name;
	పూర్ణాంకం r, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	ఒకవేళ (r == -1) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
	} లేకపోతే {
		stat_గమ్యం_attrib(&st, &a);
		send_attrib(id, &a);
		స్థితి_2 = SSH2_FX_OK;
	}
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

స్థిర శూన్య
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

స్థిర శూన్య
process_fstat(uint32_t id)
{
	Attrib a;
	నిర్మాణం stat st;
	పూర్ణాంకం fd, r, handle, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_గమ్యం_name(handle), handle);
	fd = handle_గమ్యం_fd(handle);
	ఒకవేళ (fd >= 0) {
		r = fstat(fd, &st);
		ఒకవేళ (r == -1) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
		} లేకపోతే {
			stat_గమ్యం_attrib(&st, &a);
			send_attrib(id, &a);
			స్థితి_2 = SSH2_FX_OK;
		}
	}
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		send_స్థితి(id, స్థితి_2);
}

స్థిర నిర్మాణం timeval *
attrib_గమ్యం_tv(స్థిరరాశి Attrib *a)
{
	స్థిర నిర్మాణం timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	తిరిగి tv;
}

స్థిర నిర్మాణం timespec *
attrib_గమ్యం_ts(స్థిరరాశి Attrib *a)
{
	స్థిర నిర్మాణం timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	తిరిగి ts;
}

స్థిర శూన్య
process_setstat(uint32_t id)
{
	Attrib a;
	అక్షరం *name;
	పూర్ణాంకం r, స్థితి_2 = SSH2_FX_OK;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_కొలత) {
		logit("set \"%s\" size %llu",
		    name, (గుర్తులేని దీర్ఘ దీర్ఘ)a.కొలత);
		r = truncate(name, a.కొలత);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		అక్షరం buf[64];
		time_t t = a.mtime;

		strftime(buf, పరిమాణం(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_గమ్యం_tv(&a));
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_fsetstat(uint32_t id)
{
	Attrib a;
	పూర్ణాంకం handle, fd, r;
	పూర్ణాంకం స్థితి_2 = SSH2_FX_OK;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_గమ్యం_fd(handle);
	ఒకవేళ (fd < 0)
		స్థితి_2 = SSH2_FX_FAILURE;
	లేకపోతే {
		అక్షరం *name = handle_గమ్యం_name(handle);

		ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_కొలత) {
			logit("set \"%s\" size %llu",
			    name, (గుర్తులేని దీర్ఘ దీర్ఘ)a.కొలత);
			r = ftruncate(fd, a.కొలత);
			ఒకవేళ (r == -1)
				స్థితి_2 = errno_గమ్యం_portable(errno);
		}
		ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#నిర్వచితమైతే HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#లేకపోతే
			r = chmod(name, a.perm & 07777);
#అయితే_ముగింపు
			ఒకవేళ (r == -1)
				స్థితి_2 = errno_గమ్యం_portable(errno);
		}
		ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			అక్షరం buf[64];
			time_t t = a.mtime;

			strftime(buf, పరిమాణం(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#నిర్వచితమైతే HAVE_FUTIMES
			r = futimes(fd, attrib_గమ్యం_tv(&a));
#లేకపోతే
			r = utimes(name, attrib_గమ్యం_tv(&a));
#అయితే_ముగింపు
			ఒకవేళ (r == -1)
				స్థితి_2 = errno_గమ్యం_portable(errno);
		}
		ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#నిర్వచితమైతే HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#లేకపోతే
			r = chown(name, a.uid, a.gid);
#అయితే_ముగింపు
			ఒకవేళ (r == -1)
				స్థితి_2 = errno_గమ్యం_portable(errno);
		}
	}
	send_స్థితి(id, స్థితి_2);
}

స్థిర శూన్య
process_opendir(uint32_t id)
{
	DIR *dirp = ఖాళీ;
	అక్షరం *మార్గం;
	పూర్ణాంకం r, handle, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &మార్గం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", మార్గం);
	dirp = opendir(మార్గం);
	ఒకవేళ (dirp == ఖాళీ) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
	} లేకపోతే {
		handle = handle_new(HANDLE_DIR, మార్గం, 0, 0, dirp);
		ఒకవేళ (handle < 0) {
			closedir(dirp);
		} లేకపోతే {
			send_handle(id, handle);
			స్థితి_2 = SSH2_FX_OK;
		}

	}
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		send_స్థితి(id, స్థితి_2);
	విడుదల(మార్గం);
}

స్థిర శూన్య
process_readdir(uint32_t id)
{
	DIR *dirp;
	నిర్మాణం dirent *dp;
	అక్షరం *మార్గం;
	పూర్ణాంకం r, handle;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_గమ్యం_name(handle), handle);
	dirp = handle_గమ్యం_dir(handle);
	మార్గం = handle_గమ్యం_name(handle);
	ఒకవేళ (dirp == ఖాళీ || మార్గం == ఖాళీ) {
		send_స్థితి(id, SSH2_FX_FAILURE);
	} లేకపోతే {
		నిర్మాణం stat st;
		అక్షరం *pathname;
		Stat *stats;
		పూర్ణాంకం nstats = 10, లెక్క = 0, i;

		stats = xcalloc(nstats, పరిమాణం(Stat));
		అయితే ((dp = readdir(dirp)) != ఖాళీ) {
			ఒకవేళ (లెక్క >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, పరిమాణం(Stat));
			}
			xasprintf(&pathname, "%s%s%s", మార్గం,
			    strcmp(మార్గం, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			విడుదల(pathname);
			ఒకవేళ (r == -1)
				కొనసాగు;
			stat_గమ్యం_attrib(&st, &(stats[లెక్క].attrib));
			stats[లెక్క].name = xstrdup(dp->d_name);
			stats[లెక్క].long_name = ls_file(dp->d_name, &st,
			    0, 0, ఖాళీ, ఖాళీ);
			లెక్క++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			ఒకవేళ (లెక్క == 100)
				ఆపు;
		}
		ఒకవేళ (లెక్క > 0) {
			send_పేర్లు(id, లెక్క, stats);
			కొరకు (i = 0; i < లెక్క; i++) {
				విడుదల(stats[i].name);
				విడుదల(stats[i].long_name);
			}
		} లేకపోతే {
			send_స్థితి(id, SSH2_FX_EOF);
		}
		విడుదల(stats);
	}
}

స్థిర శూన్య
process_remove(uint32_t id)
{
	అక్షరం *name;
	పూర్ణాంకం r, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_mkdir(uint32_t id)
{
	Attrib a;
	అక్షరం *name;
	పూర్ణాంకం r, బహుళకం, స్థితి_2 = SSH2_FX_FAILURE;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	బహుళకం = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, బహుళకం);
	r = mkdir(name, బహుళకం);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_rmdir(uint32_t id)
{
	అక్షరం *name;
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_realpath(uint32_t id)
{
	అక్షరం resolvedname[PATH_MAX];
	అక్షరం *మార్గం;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &మార్గం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (మార్గం[0] == '\0') {
		విడుదల(మార్గం);
		మార్గం = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", మార్గం);
	ఒకవేళ (sftp_realpath(మార్గం, resolvedname) == ఖాళీ) {
		send_స్థితి(id, errno_గమ్యం_portable(errno));
	} లేకపోతే {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_పేర్లు(id, 1, &s);
	}
	విడుదల(మార్గం);
}

స్థిర శూన్య
process_rename(uint32_t id)
{
	అక్షరం *oldpath, *newpath;
	పూర్ణాంకం r, స్థితి_2;
	నిర్మాణం stat sb;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &oldpath, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	స్థితి_2 = SSH2_FX_FAILURE;
	ఒకవేళ (lstat(oldpath, &sb) == -1)
		స్థితి_2 = errno_గమ్యం_portable(errno);
	లేకపోతే ఒకవేళ (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		ఒకవేళ (link(oldpath, newpath) == -1) {
			ఒకవేళ (errno == EOPNOTSUPP || errno == ENOSYS
#నిర్వచితమైతే EXDEV
			    || errno == EXDEV
#అయితే_ముగింపు
#నిర్వచితమైతే LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#అయితే_ముగింపు
			    ) {
				నిర్మాణం stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				ఒకవేళ (stat(newpath, &st) == -1) {
					ఒకవేళ (rename(oldpath, newpath) == -1)
						స్థితి_2 =
						    errno_గమ్యం_portable(errno);
					లేకపోతే
						స్థితి_2 = SSH2_FX_OK;
				}
			} లేకపోతే {
				స్థితి_2 = errno_గమ్యం_portable(errno);
			}
		} లేకపోతే ఒకవేళ (unlink(oldpath) == -1) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} లేకపోతే
			స్థితి_2 = SSH2_FX_OK;
	} లేకపోతే ఒకవేళ (stat(newpath, &sb) == -1) {
		ఒకవేళ (rename(oldpath, newpath) == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
		లేకపోతే
			స్థితి_2 = SSH2_FX_OK;
	}
	send_స్థితి(id, స్థితి_2);
	విడుదల(oldpath);
	విడుదల(newpath);
}

స్థిర శూన్య
process_readlink(uint32_t id)
{
	పూర్ణాంకం r, len;
	అక్షరం buf[PATH_MAX];
	అక్షరం *మార్గం;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &మార్గం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", మార్గం);
	ఒకవేళ ((len = readlink(మార్గం, buf, పరిమాణం(buf) - 1)) == -1)
		send_స్థితి(id, errno_గమ్యం_portable(errno));
	లేకపోతే {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_పేర్లు(id, 1, &s);
	}
	విడుదల(మార్గం);
}

స్థిర శూన్య
process_symlink(uint32_t id)
{
	అక్షరం *oldpath, *newpath;
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &oldpath, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(oldpath);
	విడుదల(newpath);
}

స్థిర శూన్య
process_extended_posix_rename(uint32_t id)
{
	అక్షరం *oldpath, *newpath;
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &oldpath, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(oldpath);
	విడుదల(newpath);
}

స్థిర శూన్య
process_extended_statvfs(uint32_t id)
{
	అక్షరం *మార్గం;
	నిర్మాణం statvfs st;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &మార్గం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", మార్గం);

	ఒకవేళ (statvfs(మార్గం, &st) != 0)
		send_స్థితి(id, errno_గమ్యం_portable(errno));
	లేకపోతే
		send_statvfs(id, &st);
	విడుదల(మార్గం);
}

స్థిర శూన్య
process_extended_fstatvfs(uint32_t id)
{
	పూర్ణాంకం r, handle, fd;
	నిర్మాణం statvfs st;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_గమ్యం_name(handle), handle);
	ఒకవేళ ((fd = handle_గమ్యం_fd(handle)) < 0) {
		send_స్థితి(id, SSH2_FX_FAILURE);
		తిరిగి;
	}
	ఒకవేళ (fstatvfs(fd, &st) != 0)
		send_స్థితి(id, errno_గమ్యం_portable(errno));
	లేకపోతే
		send_statvfs(id, &st);
}

స్థిర శూన్య
process_extended_hardlink(uint32_t id)
{
	అక్షరం *oldpath, *newpath;
	పూర్ణాంకం r, స్థితి_2;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &oldpath, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	send_స్థితి(id, స్థితి_2);
	విడుదల(oldpath);
	విడుదల(newpath);
}

స్థిర శూన్య
process_extended_fsync(uint32_t id)
{
	పూర్ణాంకం handle, fd, r, స్థితి_2 = SSH2_FX_OP_UNSUPPORTED;

	ఒకవేళ ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_గమ్యం_name(handle));
	ఒకవేళ ((fd = handle_గమ్యం_fd(handle)) < 0)
		స్థితి_2 = SSH2_FX_NO_SUCH_FILE;
	లేకపోతే ఒకవేళ (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		స్థితి_2 = (r == -1) ? errno_గమ్యం_portable(errno) : SSH2_FX_OK;
	}
	send_స్థితి(id, స్థితి_2);
}

స్థిర శూన్య
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	అక్షరం *name;
	పూర్ణాంకం r, స్థితి_2 = SSH2_FX_OK;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &name, ఖాళీ)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_కొలత) {
		/* nonsensical for links */
		స్థితి_2 = SSH2_FX_BAD_సందేశం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		అక్షరం buf[64];
		time_t t = a.mtime;

		strftime(buf, పరిమాణం(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_గమ్యం_ts(&a), AT_SYMLINK_NOFOLLOW);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
	ఒకవేళ (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		ఒకవేళ (r == -1)
			స్థితి_2 = errno_గమ్యం_portable(errno);
	}
 బహిర్గతం:
	send_స్థితి(id, స్థితి_2);
	విడుదల(name);
}

స్థిర శూన్య
process_extended_limits(uint32_t id)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;
	uint64_t nfiles = 0;
#ఒకవేళ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	నిర్మాణం rlimit rlim;
#అయితే_ముగింపు

	debug("request %u: limits", id);

#ఒకవేళ defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	ఒకవేళ (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#అయితే_ముగింపు

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED_జవాబు)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(సందేశం, SFTP_MAX_సందేశం_నిడివి)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(సందేశం, SFTP_MAX_READ_నిడివి)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(సందేశం, SFTP_MAX_సందేశం_నిడివి - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(సందేశం, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
process_extended_expand(uint32_t id)
{
	అక్షరం cwd[PATH_MAX], resolvedname[PATH_MAX];
	అక్షరం *మార్గం, *npath;
	పూర్ణాంకం r;
	Stat s;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &మార్గం, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (getcwd(cwd, పరిమాణం(cwd)) == ఖాళీ) {
		send_స్థితి(id, errno_గమ్యం_portable(errno));
		వెళ్ళు బహిర్గతం;
	}

	debug3("request %u: expand, original \"%s\"", id, మార్గం);
	ఒకవేళ (మార్గం[0] == '\0') {
		/* empty path */
		విడుదల(మార్గం);
		మార్గం = xstrdup(".");
	} లేకపోతే ఒకవేళ (*మార్గం == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		ఒకవేళ (strcmp(మార్గం, "~") == 0) {
			విడుదల(మార్గం);
			మార్గం = xstrdup(cwd);
		} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(మార్గం, "~/", 2) == 0) {
			npath = xstrdup(మార్గం + 2);
			విడుదల(మార్గం);
			xasprintf(&మార్గం, "%s/%s", cwd, npath);
			విడుదల(npath);
		} లేకపోతే {
			/* ~user expansions */
			ఒకవేళ (tilde_expand(మార్గం, pw->pw_uid, &npath) != 0) {
				send_స్థితి_errmsg(id,
				    errno_గమ్యం_portable(ENOENT), "no such user");
				వెళ్ళు బహిర్గతం;
			}
			విడుదల(మార్గం);
			మార్గం = npath;
		}
	} లేకపోతే ఒకవేళ (*మార్గం != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, మార్గం);
		విడుదల(మార్గం);
		మార్గం = npath;
	}
	verbose("expand \"%s\"", మార్గం);
	ఒకవేళ (sftp_realpath(మార్గం, resolvedname) == ఖాళీ) {
		send_స్థితి(id, errno_గమ్యం_portable(errno));
		వెళ్ళు బహిర్గతం;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_పేర్లు(id, 1, &s);
 బహిర్గతం:
	విడుదల(మార్గం);
}

స్థిర శూన్య
process_extended_copy_దత్తాంశం(uint32_t id)
{
	u_char buf[64*1024];
	పూర్ణాంకం read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	పూర్ణాంకం r, copy_until_eof, స్థితి_2 = SSH2_FX_OP_UNSUPPORTED;
	కొలత_t ret;
	నిర్మాణం stat st_read, st_write;

	ఒకవేళ ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_గమ్యం_name(read_handle), read_handle,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)read_off, (గుర్తులేని దీర్ఘ దీర్ఘ)read_len,
	    handle_గమ్యం_name(write_handle), write_handle,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)write_off);

	/* For read length of 0, we read until EOF. */
	ఒకవేళ (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} లేకపోతే
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_గమ్యం_fd(read_handle);
	write_fd = handle_గమ్యం_fd(write_handle);
	ఒకవేళ (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		స్థితి_2 = errno_గమ్యం_portable(EBADF);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fstat(read_fd, &st_read) != 0) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fstat(write_fd, &st_write) != 0) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (read_handle == write_handle ||
	    !strcmp(handle_గమ్యం_name(read_handle), handle_గమ్యం_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_గమ్యం_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_గమ్యం_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		స్థితి_2 = SSH2_FX_FAILURE;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (lseek(read_fd, read_off, SEEK_SET) < 0) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("read_seek failed");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((handle_గమ్యం_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		స్థితి_2 = errno_గమ్యం_portable(errno);
		error_f("write_seek failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Process the request in chunks. */
	అయితే (read_len > 0 || copy_until_eof) {
		len = MINIMUM(పరిమాణం(buf), read_len);
		read_len -= len;

		ret = atomicio(పఠ, read_fd, buf, len);
		ఒకవేళ (ret == 0 && errno == EPIPE) {
			స్థితి_2 = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			ఆపు;
		} లేకపోతే ఒకవేళ (ret == 0) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
			error_f("read failed: %s", strerror(errno));
			ఆపు;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		ఒకవేళ (ret != len) {
			స్థితి_2 = errno_గమ్యం_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ret, (గుర్తులేని దీర్ఘ దీర్ఘ)len,
			    strerror(errno));
			ఆపు;
		}
		handle_update_write(write_handle, len);
	}

	ఒకవేళ (read_len == 0)
		స్థితి_2 = SSH2_FX_OK;

 బహిర్గతం:
	send_స్థితి(id, స్థితి_2);
}

స్థిర శూన్య
process_extended_home_directory(uint32_t id)
{
	అక్షరం *username;
	నిర్మాణం passwd *user_pw;
	పూర్ణాంకం r;
	Stat s;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &username, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	ఒకవేళ (username[0] == '\0') {
		user_pw = pw;
	} లేకపోతే ఒకవేళ ((user_pw = getpwnam(username)) == ఖాళీ) {
		send_స్థితి(id, SSH2_FX_FAILURE);
		వెళ్ళు బహిర్గతం;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_పేర్లు(id, 1, &s);
 బహిర్గతం:
	విడుదల(username);
}

స్థిర శూన్య
process_extended_get_users_groups_by_id(uint32_t id)
{
	నిర్మాణం passwd *user_pw;
	నిర్మాణం సమూహం *gr;
	నిర్మాణం sshbuf *uids, *gids, *usernames, *groupnames, *సందేశం;
	పూర్ణాంకం r;
	u_int n, nusers = 0, ngroups = 0;
	స్థిరరాశి అక్షరం *name;

	ఒకవేళ ((usernames = sshbuf_new()) == ఖాళీ ||
	    (groupnames = sshbuf_new()) == ఖాళీ ||
	    (సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	అయితే (sshbuf_len(uids) != 0) {
		ఒకవేళ ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == ఖాళీ ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		ఒకవేళ ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	అయితే (sshbuf_len(gids) != 0) {
		ఒకవేళ ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == ఖాళీ ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		ఒకవేళ ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED_జవాబు)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(సందేశం);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
process_extended(uint32_t id)
{
	అక్షరం *request;
	పూర్ణాంకం r;
	స్థిరరాశి నిర్మాణం sftp_handler *exthand;

	ఒకవేళ ((r = sshbuf_get_cstring(iqueue, &request, ఖాళీ)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ ((exthand = extended_handler_byname(request)) == ఖాళీ) {
		error("Unknown extended request \"%.100s\"", request);
		send_స్థితి(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} లేకపోతే {
		ఒకవేళ (!request_permitted(exthand))
			send_స్థితి(id, SSH2_FX_PERMISSION_DENIED);
		లేకపోతే
			exthand->handler(id);
	}
	విడుదల(request);
}

/* stolen from ssh-agent */

స్థిర శూన్య
process(శూన్య)
{
	u_int సందేశం_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	స్థిరరాశి u_char *cp;
	పూర్ణాంకం i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	ఒకవేళ (buf_len < 5)
		తిరిగి;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	సందేశం_len = get_u32(cp);
	ఒకవేళ (సందేశం_len > SFTP_MAX_సందేశం_నిడివి) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	ఒకవేళ (buf_len < సందేశం_len + 4)
		తిరిగి;
	ఒకవేళ ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	ఒకవేళ ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	ఎంపిక (type) {
	స్థితి SSH2_FXP_INIT:
		process_init();
		init_పూర్తి = 1;
		ఆపు;
	స్థితి SSH2_FXP_EXTENDED:
		ఒకవేళ (!init_పూర్తి)
			fatal("Received extended request before init");
		ఒకవేళ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		ఆపు;
	అప్రమేయ:
		ఒకవేళ (!init_పూర్తి)
			fatal("Received %u request before init", type);
		ఒకవేళ ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		కొరకు (i = 0; handlers[i].handler != ఖాళీ; i++) {
			ఒకవేళ (type == handlers[i].type) {
				ఒకవేళ (!request_permitted(&handlers[i])) {
					send_స్థితి(id,
					    SSH2_FX_PERMISSION_DENIED);
				} లేకపోతే {
					handlers[i].handler(id);
				}
				ఆపు;
			}
		}
		ఒకవేళ (handlers[i].handler == ఖాళీ)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	ఒకవేళ (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	ఒకవేళ (సందేశం_len < consumed) {
		error("msg_len %u < consumed %u", సందేశం_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	ఒకవేళ (సందేశం_len > consumed &&
	    (r = sshbuf_consume(iqueue, సందేశం_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
శూన్య
sftp_server_cleanup_exit(పూర్ణాంకం i)
{
	ఒకవేళ (pw != ఖాళీ && client_addr != ఖాళీ) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

స్థిర శూన్య
sftp_server_usage(శూన్య)
{
	బాహ్య అక్షరం *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	నిష్క్రమించు(1);
}

పూర్ణాంకం
sftp_server_main(పూర్ణాంకం argc, అక్షరం **argv, నిర్మాణం passwd *user_pw)
{
	పూర్ణాంకం i, r, లోపల, బహిర్గతం, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	అక్షరం *cp, *homedir = ఖాళీ, uidstr[32], buf[4*4096];
	దీర్ఘ ముసుగు;

	బాహ్య అక్షరం *optarg;
	బాహ్య అక్షరం *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	అయితే (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'Q':
			ఒకవేళ (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				నిష్క్రమించు(1);
			}
			కొరకు (i = 0; handlers[i].handler != ఖాళీ; i++)
				రాయి("%s\n", handlers[i].name);
			కొరకు (i = 0; extended_handlers[i].handler != ఖాళీ; i++)
				రాయి("%s\n", extended_handlers[i].name);
			నిష్క్రమించు(0);
			ఆపు;
		స్థితి 'R':
			readonly = 1;
			ఆపు;
		స్థితి 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			ఆపు;
		స్థితి 'e':
			log_stderr = 1;
			ఆపు;
		స్థితి 'l':
			log_level = log_level_సంఖ్య(optarg);
			ఒకవేళ (log_level == SYSLOG_LEVEL_NOT_సమితి)
				error("Invalid log level \"%s\"", optarg);
			ఆపు;
		స్థితి 'f':
			log_facility = log_facility_సంఖ్య(optarg);
			ఒకవేళ (log_facility == SYSLOG_FACILITY_NOT_సమితి)
				error("Invalid log facility \"%s\"", optarg);
			ఆపు;
		స్థితి 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, పరిమాణం(uidstr), "%llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (అక్షరం *)ఖాళీ);
			విడుదల(cp);
			ఆపు;
		స్థితి 'p':
			ఒకవేళ (request_allowlist != ఖాళీ)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			ఆపు;
		స్థితి 'P':
			ఒకవేళ (request_denylist != ఖాళీ)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			ఆపు;
		స్థితి 'u':
			errno = 0;
			ముసుగు = strtol(optarg, &cp, 8);
			ఒకవేళ (ముసుగు < 0 || ముసుగు > 0777 || *cp != '\0' ||
			    cp == optarg || (ముసుగు == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(శూన్య)umask((బహుళకం_t)ముసుగు);
			ఆపు;
		స్థితి 'h':
		అప్రమేయ:
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

	ఒకవేళ ((cp = getenv("SSH_CONNECTION")) != ఖాళీ) {
		client_addr = xstrdup(cp);
		ఒకవేళ ((cp = strchr(client_addr, ' ')) == ఖాళీ) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} లేకపోతే
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	లోపల = STDIN_FILENO;
	బహిర్గతం = STDOUT_FILENO;

#నిర్వచితమైతే HAVE_CYGWIN
	setmode(లోపల, O_ద్విమాన);
	setmode(బహిర్గతం, O_ద్విమాన);
#అయితే_ముగింపు

	ఒకవేళ ((iqueue = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((oqueue = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	ఒకవేళ (homedir != ఖాళీ) {
		ఒకవేళ (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	కొరకు (;;) {
		నిర్మాణం pollfd pfd[2];

		memset(pfd, 0, పరిమాణం pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		ఒకవేళ ((r = sshbuf_check_reserve(iqueue, పరిమాణం(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_సందేశం_నిడివి)) == 0) {
			pfd[0].fd = లోపల;
			pfd[0].events = POLLIN;
		}
		లేకపోతే ఒకవేళ (r != SSH_ERR_NO_బఫరు_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		ఒకవేళ (olen > 0) {
			pfd[1].fd = బహిర్గతం;
			pfd[1].events = POLLOUT;
		}

		ఒకవేళ (poll(pfd, 2, -1) == -1) {
			ఒకవేళ (errno == EINTR)
				కొనసాగు;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		ఒకవేళ (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = పఠ(లోపల, buf, పరిమాణం buf);
			ఒకవేళ (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} లేకపోతే ఒకవేళ (len == -1) {
				ఒకవేళ (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} లేకపోతే ఒకవేళ ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		ఒకవేళ (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = లిఖ(బహిర్గతం, sshbuf_ptr(oqueue), olen);
			ఒకవేళ (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} లేకపోతే ఒకవేళ (len == -1) {
				sftp_server_cleanup_exit(1);
				ఒకవేళ (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} లేకపోతే ఒకవేళ ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_సందేశం_నిడివి);
		ఒకవేళ (r == 0)
			process();
		లేకపోతే ఒకవేళ (r != SSH_ERR_NO_బఫరు_SPACE)
			fatal_fr(r, "reserve");
	}
}
