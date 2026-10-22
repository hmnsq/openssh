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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/statvfs.h>

#अन्तर्भाव <dirent.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <grp.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "uidswap.h"

#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"

वर्ण *sftp_realpath(ध्रुव वर्ण *, वर्ण *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#परिभाषय SFTP_MAX_READ_दीर्घता (SFTP_MAX_सन्देशः_दीर्घता - 1024)

/* Our verbosity */
स्थिर LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
स्थिर संरचना passwd *pw = रिक्त;
स्थिर वर्ण *client_addr = रिक्त;

/* input and output queue */
संरचना sshbuf *iqueue;
संरचना sshbuf *oqueue;

/* Version of client */
स्थिर u_int संस्करणम्;

/* SSH2_FXP_INIT received */
स्थिर पूर्णाङ्क init_समाप्तम्;

/* Disable writes */
स्थिर पूर्णाङ्क readonly;

/* Requests that are allowed/denied */
स्थिर वर्ण *request_allowlist, *request_denylist;

/* portable attributes, etc. */
प्रकारनिर्देश संरचना Stat Stat;

संरचना Stat {
	वर्ण *name;
	वर्ण *long_name;
	Attrib attrib;
};

/* Packet handlers */
स्थिर शून्य process_open(uint32_t id);
स्थिर शून्य process_close(uint32_t id);
स्थिर शून्य process_read(uint32_t id);
स्थिर शून्य process_write(uint32_t id);
स्थिर शून्य process_stat(uint32_t id);
स्थिर शून्य process_lstat(uint32_t id);
स्थिर शून्य process_fstat(uint32_t id);
स्थिर शून्य process_setstat(uint32_t id);
स्थिर शून्य process_fsetstat(uint32_t id);
स्थिर शून्य process_opendir(uint32_t id);
स्थिर शून्य process_readdir(uint32_t id);
स्थिर शून्य process_remove(uint32_t id);
स्थिर शून्य process_mkdir(uint32_t id);
स्थिर शून्य process_rmdir(uint32_t id);
स्थिर शून्य process_realpath(uint32_t id);
स्थिर शून्य process_rename(uint32_t id);
स्थिर शून्य process_readlink(uint32_t id);
स्थिर शून्य process_symlink(uint32_t id);
स्थिर शून्य process_extended_posix_rename(uint32_t id);
स्थिर शून्य process_extended_statvfs(uint32_t id);
स्थिर शून्य process_extended_fstatvfs(uint32_t id);
स्थिर शून्य process_extended_hardlink(uint32_t id);
स्थिर शून्य process_extended_fsync(uint32_t id);
स्थिर शून्य process_extended_lsetstat(uint32_t id);
स्थिर शून्य process_extended_limits(uint32_t id);
स्थिर शून्य process_extended_expand(uint32_t id);
स्थिर शून्य process_extended_copy_दत्त(uint32_t id);
स्थिर शून्य process_extended_home_directory(uint32_t id);
स्थिर शून्य process_extended_get_users_groups_by_id(uint32_t id);
स्थिर शून्य process_extended(uint32_t id);

संरचना sftp_handler {
	ध्रुव वर्ण *name;	/* user-visible name for fine-grained perms */
	ध्रुव वर्ण *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	शून्य (*handler)(uint32_t);
	पूर्णाङ्क does_write;		/* if nonzero, banned for readonly mode */
};

स्थिर ध्रुव संरचना sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", रिक्त, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", रिक्त, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", रिक्त, SSH2_FXP_READ, process_read, 0 },
	{ "write", रिक्त, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", रिक्त, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", रिक्त, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", रिक्त, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", रिक्त, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", रिक्त, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", रिक्त, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", रिक्त, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", रिक्त, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", रिक्त, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", रिक्त, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", रिक्त, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", रिक्त, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", रिक्त, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", रिक्त, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ रिक्त, रिक्त, 0, रिक्त, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
स्थिर ध्रुव संरचना sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_दत्त, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ रिक्त, रिक्त, 0, रिक्त, 0 }
};

स्थिर ध्रुव संरचना sftp_handler *
extended_handler_byname(ध्रुव वर्ण *name)
{
	पूर्णाङ्क i;

	प्रति (i = 0; extended_handlers[i].handler != रिक्त; i++) {
		यदि (वाक्यं_तुलय(name, extended_handlers[i].ext_name) == 0)
			प्रत्यागम &extended_handlers[i];
	}
	प्रत्यागम रिक्त;
}

स्थिर पूर्णाङ्क
request_permitted(ध्रुव संरचना sftp_handler *h)
{
	वर्ण *परिणाम;

	यदि (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		प्रत्यागम 0;
	}
	यदि (request_denylist != रिक्त &&
	    ((परिणाम = मेलनम्_list(h->name, request_denylist, रिक्त))) != रिक्त) {
		मुक्त(परिणाम);
		verbose("Refusing denylisted %s request", h->name);
		प्रत्यागम 0;
	}
	यदि (request_allowlist != रिक्त &&
	    ((परिणाम = मेलनम्_list(h->name, request_allowlist, रिक्त))) != रिक्त) {
		मुक्त(परिणाम);
		debug2("Permitting allowlisted %s request", h->name);
		प्रत्यागम 1;
	}
	यदि (request_allowlist != रिक्त) {
		verbose("Refusing non-allowlisted %s request", h->name);
		प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
errno_गन्तव्यम्_portable(पूर्णाङ्क unixerrno)
{
	पूर्णाङ्क ret = 0;

	विकल्प (unixerrno) {
	पक्ष 0:
		ret = SSH2_FX_OK;
		भङ्ग;
	पक्ष ENOENT:
	पक्ष ENOTDIR:
	पक्ष EBADF:
	पक्ष ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		भङ्ग;
	पक्ष EPERM:
	पक्ष EACCES:
	पक्ष EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		भङ्ग;
	पक्ष ENAMETOOLONG:
	पक्ष EINVAL:
		ret = SSH2_FX_BAD_सन्देशः;
		भङ्ग;
	पक्ष ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		भङ्ग;
	स्वभाव:
		ret = SSH2_FX_FAILURE;
		भङ्ग;
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
flags_from_portable(पूर्णाङ्क pflags)
{
	पूर्णाङ्क flags = 0;

	यदि ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} अन्यथा यदि (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} अन्यथा यदि (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	यदि (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	यदि (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	यदि (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	यदि (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	प्रत्यागम flags;
}

स्थिर ध्रुव वर्ण *
string_from_portable(पूर्णाङ्क pflags)
{
	स्थिर वर्ण ret[128];

	*ret = '\0';

#परिभाषय PAPPEND(str)	{				\
		यदि (*ret != '\0')			\
			strlcat(ret, ",", परिमाण(ret));	\
		strlcat(ret, str, परिमाण(ret));		\
	}

	यदि (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	यदि (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	यदि (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	यदि (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	यदि (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	यदि (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	प्रत्यागम ret;
}

/* handle handles */

प्रकारनिर्देश संरचना Handle Handle;
संरचना Handle {
	पूर्णाङ्क use;
	DIR *dirp;
	पूर्णाङ्क fd;
	पूर्णाङ्क flags;
	वर्ण *name;
	uint64_t अष्टकानि_read, अष्टकानि_write;
	पूर्णाङ्क अग्र_अप्रयुक्तम्;
};

गणना {
	HANDLE_अप्रयुक्तम्,
	HANDLE_DIR,
	HANDLE_FILE
};

स्थिर Handle *handles = रिक्त;
स्थिर u_int अङ्कः_handles = 0;
स्थिर पूर्णाङ्क first_अप्रयुक्तम्_handle = -1;

स्थिर शून्य handle_अप्रयुक्तम्(पूर्णाङ्क i)
{
	handles[i].use = HANDLE_अप्रयुक्तम्;
	handles[i].अग्र_अप्रयुक्तम् = first_अप्रयुक्तम्_handle;
	first_अप्रयुक्तम्_handle = i;
}

स्थिर पूर्णाङ्क
handle_new(पूर्णाङ्क use, ध्रुव वर्ण *name, पूर्णाङ्क fd, पूर्णाङ्क flags, DIR *dirp)
{
	पूर्णाङ्क i;

	यदि (first_अप्रयुक्तम्_handle == -1) {
		यदि (अङ्कः_handles + 1 <= अङ्कः_handles)
			प्रत्यागम -1;
		अङ्कः_handles++;
		handles = xreallocarray(handles, अङ्कः_handles, परिमाण(Handle));
		handle_अप्रयुक्तम्(अङ्कः_handles - 1);
	}

	i = first_अप्रयुक्तम्_handle;
	first_अप्रयुक्तम्_handle = handles[i].अग्र_अप्रयुक्तम्;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].अष्टकानि_read = handles[i].अष्टकानि_write = 0;

	प्रत्यागम i;
}

स्थिर पूर्णाङ्क
handle_is_ok(पूर्णाङ्क i, पूर्णाङ्क type)
{
	प्रत्यागम i >= 0 && (u_int)i < अङ्कः_handles && handles[i].use == type;
}

स्थिर पूर्णाङ्क
handle_गन्तव्यम्_string(पूर्णाङ्क handle, u_char **stringp, पूर्णाङ्क *hlenp)
{
	यदि (stringp == रिक्त || hlenp == रिक्त)
		प्रत्यागम -1;
	*stringp = xmalloc(परिमाण(int32_t));
	put_u32(*stringp, handle);
	*hlenp = परिमाण(int32_t);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
handle_from_string(ध्रुव u_char *handle, u_int hlen)
{
	पूर्णाङ्क val;

	यदि (hlen != परिमाण(int32_t))
		प्रत्यागम -1;
	val = get_u32(handle);
	यदि (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		प्रत्यागम val;
	प्रत्यागम -1;
}

स्थिर वर्ण *
handle_गन्तव्यम्_name(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		प्रत्यागम handles[handle].name;
	प्रत्यागम रिक्त;
}

स्थिर DIR *
handle_गन्तव्यम्_dir(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_DIR))
		प्रत्यागम handles[handle].dirp;
	प्रत्यागम रिक्त;
}

स्थिर पूर्णाङ्क
handle_गन्तव्यम्_fd(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_FILE))
		प्रत्यागम handles[handle].fd;
	प्रत्यागम -1;
}

स्थिर पूर्णाङ्क
handle_गन्तव्यम्_flags(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_FILE))
		प्रत्यागम handles[handle].flags;
	प्रत्यागम 0;
}

स्थिर शून्य
handle_update_read(पूर्णाङ्क handle, ssize_t अष्टकानि)
{
	यदि (handle_is_ok(handle, HANDLE_FILE) && अष्टकानि > 0)
		handles[handle].अष्टकानि_read += अष्टकानि;
}

स्थिर शून्य
handle_update_write(पूर्णाङ्क handle, ssize_t अष्टकानि)
{
	यदि (handle_is_ok(handle, HANDLE_FILE) && अष्टकानि > 0)
		handles[handle].अष्टकानि_write += अष्टकानि;
}

स्थिर uint64_t
handle_अष्टकानि_read(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_FILE))
		प्रत्यागम (handles[handle].अष्टकानि_read);
	प्रत्यागम 0;
}

स्थिर uint64_t
handle_अष्टकानि_write(पूर्णाङ्क handle)
{
	यदि (handle_is_ok(handle, HANDLE_FILE))
		प्रत्यागम (handles[handle].अष्टकानि_write);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
handle_close(पूर्णाङ्क handle)
{
	पूर्णाङ्क ret = -1;

	यदि (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		मुक्त(handles[handle].name);
		handle_अप्रयुक्तम्(handle);
	} अन्यथा यदि (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		मुक्त(handles[handle].name);
		handle_अप्रयुक्तम्(handle);
	} अन्यथा {
		errno = ENOENT;
	}
	प्रत्यागम ret;
}

स्थिर शून्य
handle_log_close(पूर्णाङ्क handle, वर्ण *emsg)
{
	यदि (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == रिक्त ? "" : emsg, emsg == रिक्त ? "" : " ",
		    handle_गन्तव्यम्_name(handle),
		    (अचिह्नित दीर्घ दीर्घ)handle_अष्टकानि_read(handle),
		    (अचिह्नित दीर्घ दीर्घ)handle_अष्टकानि_write(handle));
	} अन्यथा {
		logit("%s%sclosedir \"%s\"",
		    emsg == रिक्त ? "" : emsg, emsg == रिक्त ? "" : " ",
		    handle_गन्तव्यम्_name(handle));
	}
}

स्थिर शून्य
handle_log_exit(शून्य)
{
	u_int i;

	प्रति (i = 0; i < अङ्कः_handles; i++)
		यदि (handles[i].use != HANDLE_अप्रयुक्तम्)
			handle_log_close(i, "forced");
}

स्थिर पूर्णाङ्क
get_handle(संरचना sshbuf *queue, पूर्णाङ्क *hp)
{
	u_char *handle;
	पूर्णाङ्क r;
	आकार_t hlen;

	*hp = -1;
	यदि ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		प्रत्यागम r;
	यदि (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	मुक्त(handle);
	प्रत्यागम 0;
}

/* send replies */

स्थिर शून्य
send_सन्देशः(संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

स्थिर ध्रुव वर्ण *
स्थितिः_गन्तव्यम्_सन्देशः(uint32_t स्थितिः)
{
	स्थिर ध्रुव वर्ण * ध्रुव स्थितिः_messages[] = {
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
	प्रत्यागम (स्थितिः_messages[MINIMUM(स्थितिः,SSH2_FX_MAX)]);
}

स्थिर शून्य
send_स्थितिः_errmsg(uint32_t id, uint32_t स्थितिः, ध्रुव वर्ण *errmsg)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	debug3("request %u: sent status %u", id, स्थितिः);
	यदि (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (स्थितिः != SSH2_FX_OK && स्थितिः != SSH2_FX_EOF))
		logit("sent status %s", स्थितिः_गन्तव्यम्_सन्देशः(स्थितिः));
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_स्थितिः)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, स्थितिः)) != 0)
		fatal_fr(r, "compose");
	यदि (संस्करणम् >= 3) {
		यदि ((r = sshbuf_put_cstring(सन्देशः, errmsg == रिक्त ?
		    स्थितिः_गन्तव्यम्_सन्देशः(स्थितिः) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
send_स्थितिः(uint32_t id, uint32_t स्थितिः)
{
	send_स्थितिः_errmsg(id, स्थितिः, रिक्त);
}

स्थिर शून्य
send_दत्त_or_handle(वर्ण type, uint32_t id, ध्रुव u_char *दत्त, पूर्णाङ्क dlen)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, type)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, दत्त, dlen)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
send_दत्त(uint32_t id, ध्रुव u_char *दत्त, पूर्णाङ्क dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_दत्त_or_handle(SSH2_FXP_दत्त, id, दत्त, dlen);
}

स्थिर शून्य
send_handle(uint32_t id, पूर्णाङ्क handle)
{
	u_char *string;
	पूर्णाङ्क hlen;

	handle_गन्तव्यम्_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_दत्त_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	मुक्त(string);
}

स्थिर शून्य
send_नामानि(uint32_t id, पूर्णाङ्क गणनम्, ध्रुव Stat *stats)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क i, r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, गणनम्)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, गणनम्);
	प्रति (i = 0; i < गणनम्; i++) {
		यदि ((r = sshbuf_put_cstring(सन्देशः, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(सन्देशः, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
send_attrib(uint32_t id, ध्रुव Attrib *a)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = encode_attrib(सन्देशः, a)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
send_statvfs(uint32_t id, संरचना statvfs *st)
{
	संरचना sshbuf *सन्देशः;
	uint64_t flag;
	पूर्णाङ्क r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED_प्रत्युत्तरम्)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_खण्डानि)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, FSID_गन्तव्यम्_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, flag)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
स्थिर पूर्णाङ्क
compose_extension(संरचना sshbuf *सन्देशः, ध्रुव वर्ण *name, ध्रुव वर्ण *ver)
{
	पूर्णाङ्क r;
	ध्रुव संरचना sftp_handler *exthnd;

	यदि ((exthnd = extended_handler_byname(name)) == रिक्त)
		fatal_f("internal error: no handler for %s", name);
	यदि (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		प्रत्यागम 0;
	}
	यदि ((r = sshbuf_put_cstring(सन्देशः, name)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	प्रत्यागम 0;
}

/* parse incoming */

स्थिर शून्य
process_init(शून्य)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_u32(iqueue, &संस्करणम्)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", संस्करणम्);
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, SSH2_FILEXFER_संस्करणम्)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(सन्देशः, "posix-rename@openssh.com", "1");
	compose_extension(सन्देशः, "statvfs@openssh.com", "2");
	compose_extension(सन्देशः, "fstatvfs@openssh.com", "2");
	compose_extension(सन्देशः, "hardlink@openssh.com", "1");
	compose_extension(सन्देशः, "fsync@openssh.com", "1");
	compose_extension(सन्देशः, "lsetstat@openssh.com", "1");
	compose_extension(सन्देशः, "limits@openssh.com", "1");
	compose_extension(सन्देशः, "expand-path@openssh.com", "1");
	compose_extension(सन्देशः, "copy-data", "1");
	compose_extension(सन्देशः, "home-directory", "1");
	compose_extension(सन्देशः, "users-groups-by-id@openssh.com", "1");

	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	वर्ण *name;
	पूर्णाङ्क r, handle, fd, flags, बहुलकम्, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	बहुलकम् = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), बहुलकम्);
	यदि (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		स्थितिः = SSH2_FX_PERMISSION_DENIED;
	} अन्यथा {
		fd = उद्घाटय(name, flags, बहुलकम्);
		यदि (fd == -1) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
		} अन्यथा {
			handle = handle_new(HANDLE_FILE, name, fd, flags, रिक्त);
			यदि (handle < 0) {
				close(fd);
			} अन्यथा {
				send_handle(id, handle);
				स्थितिः = SSH2_FX_OK;
			}
		}
	}
	यदि (स्थितिः != SSH2_FX_OK)
		send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_close(uint32_t id)
{
	पूर्णाङ्क r, handle, ret, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, रिक्त);
	ret = handle_close(handle);
	स्थितिः = (ret == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
}

स्थिर शून्य
process_read(uint32_t id)
{
	स्थिर u_char *buf;
	स्थिर आकार_t buflen;
	uint32_t len;
	पूर्णाङ्क r, handle, fd, ret, स्थितिः = SSH2_FX_FAILURE;
	uint64_t off;

	यदि ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_गन्तव्यम्_name(handle), handle, (अचिह्नित दीर्घ दीर्घ)off, len);
	यदि ((fd = handle_गन्तव्यम्_fd(handle)) == -1)
		गच्छ बहिर्गमनम्;
	यदि (len > SFTP_MAX_READ_दीर्घता) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_दीर्घता);
		len = SFTP_MAX_READ_दीर्घता;
	}
	यदि (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		यदि ((buf = realloc(buf, len)) == रिक्त)
			fatal_f("realloc failed");
		buflen = len;
	}
	यदि (lseek(fd, off, SEEK_SET) == -1) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("seek \"%.100s\": %s", handle_गन्तव्यम्_name(handle),
		    strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} अन्यथा यदि ((ret = पठ(fd, buf, len)) == -1) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("read \"%.100s\": %s", handle_गन्तव्यम्_name(handle),
		    strerror(errno));
		गच्छ बहिर्गमनम्;
	} अन्यथा यदि (ret == 0) {
		स्थितिः = SSH2_FX_EOF;
		गच्छ बहिर्गमनम्;
	}
	send_दत्त(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	स्थितिः = SSH2_FX_OK;
 बहिर्गमनम्:
	यदि (स्थितिः != SSH2_FX_OK)
		send_स्थितिः(id, स्थितिः);
}

स्थिर शून्य
process_write(uint32_t id)
{
	uint64_t off;
	आकार_t len;
	पूर्णाङ्क r, handle, fd, ret, स्थितिः;
	u_char *दत्त;

	यदि ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &दत्त, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_गन्तव्यम्_name(handle), handle, (अचिह्नित दीर्घ दीर्घ)off, len);
	fd = handle_गन्तव्यम्_fd(handle);

	यदि (fd < 0)
		स्थितिः = SSH2_FX_FAILURE;
	अन्यथा {
		यदि (!(handle_गन्तव्यम्_flags(handle) & O_APPEND) &&
		    lseek(fd, off, SEEK_SET) == -1) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
			error_f("seek \"%.100s\": %s", handle_गन्तव्यम्_name(handle),
			    strerror(errno));
		} अन्यथा {
/* XXX ATOMICIO ? */
			ret = लिख(fd, दत्त, len);
			यदि (ret == -1) {
				स्थितिः = errno_गन्तव्यम्_portable(errno);
				error_f("write \"%.100s\": %s",
				    handle_गन्तव्यम्_name(handle), strerror(errno));
			} अन्यथा यदि ((आकार_t)ret == len) {
				स्थितिः = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} अन्यथा {
				debug2_f("nothing at all written");
				स्थितिः = SSH2_FX_FAILURE;
			}
		}
	}
	send_स्थितिः(id, स्थितिः);
	मुक्त(दत्त);
}

स्थिर शून्य
process_do_stat(uint32_t id, पूर्णाङ्क do_lstat)
{
	Attrib a;
	संरचना stat st;
	वर्ण *name;
	पूर्णाङ्क r, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	यदि (r == -1) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
	} अन्यथा {
		stat_गन्तव्यम्_attrib(&st, &a);
		send_attrib(id, &a);
		स्थितिः = SSH2_FX_OK;
	}
	यदि (स्थितिः != SSH2_FX_OK)
		send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

स्थिर शून्य
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

स्थिर शून्य
process_fstat(uint32_t id)
{
	Attrib a;
	संरचना stat st;
	पूर्णाङ्क fd, r, handle, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_गन्तव्यम्_name(handle), handle);
	fd = handle_गन्तव्यम्_fd(handle);
	यदि (fd >= 0) {
		r = fstat(fd, &st);
		यदि (r == -1) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
		} अन्यथा {
			stat_गन्तव्यम्_attrib(&st, &a);
			send_attrib(id, &a);
			स्थितिः = SSH2_FX_OK;
		}
	}
	यदि (स्थितिः != SSH2_FX_OK)
		send_स्थितिः(id, स्थितिः);
}

स्थिर संरचना timeval *
attrib_गन्तव्यम्_tv(ध्रुव Attrib *a)
{
	स्थिर संरचना timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	प्रत्यागम tv;
}

स्थिर संरचना timespec *
attrib_गन्तव्यम्_ts(ध्रुव Attrib *a)
{
	स्थिर संरचना timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	प्रत्यागम ts;
}

स्थिर शून्य
process_setstat(uint32_t id)
{
	Attrib a;
	वर्ण *name;
	पूर्णाङ्क r, स्थितिः = SSH2_FX_OK;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	यदि (a.flags & SSH2_FILEXFER_ATTR_आकार) {
		logit("set \"%s\" size %llu",
		    name, (अचिह्नित दीर्घ दीर्घ)a.आकार);
		r = truncate(name, a.आकार);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		वर्ण buf[64];
		time_t t = a.mtime;

		strftime(buf, परिमाण(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_गन्तव्यम्_tv(&a));
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_fsetstat(uint32_t id)
{
	Attrib a;
	पूर्णाङ्क handle, fd, r;
	पूर्णाङ्क स्थितिः = SSH2_FX_OK;

	यदि ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_गन्तव्यम्_fd(handle);
	यदि (fd < 0)
		स्थितिः = SSH2_FX_FAILURE;
	अन्यथा {
		वर्ण *name = handle_गन्तव्यम्_name(handle);

		यदि (a.flags & SSH2_FILEXFER_ATTR_आकार) {
			logit("set \"%s\" size %llu",
			    name, (अचिह्नित दीर्घ दीर्घ)a.आकार);
			r = ftruncate(fd, a.आकार);
			यदि (r == -1)
				स्थितिः = errno_गन्तव्यम्_portable(errno);
		}
		यदि (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#यदि_परिभाषितम् HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#अन्यथा
			r = chmod(name, a.perm & 07777);
#यदि_अन्तः
			यदि (r == -1)
				स्थितिः = errno_गन्तव्यम्_portable(errno);
		}
		यदि (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			वर्ण buf[64];
			time_t t = a.mtime;

			strftime(buf, परिमाण(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#यदि_परिभाषितम् HAVE_FUTIMES
			r = futimes(fd, attrib_गन्तव्यम्_tv(&a));
#अन्यथा
			r = utimes(name, attrib_गन्तव्यम्_tv(&a));
#यदि_अन्तः
			यदि (r == -1)
				स्थितिः = errno_गन्तव्यम्_portable(errno);
		}
		यदि (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#यदि_परिभाषितम् HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#अन्यथा
			r = chown(name, a.uid, a.gid);
#यदि_अन्तः
			यदि (r == -1)
				स्थितिः = errno_गन्तव्यम्_portable(errno);
		}
	}
	send_स्थितिः(id, स्थितिः);
}

स्थिर शून्य
process_opendir(uint32_t id)
{
	DIR *dirp = रिक्त;
	वर्ण *मार्गः;
	पूर्णाङ्क r, handle, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = sshbuf_get_cstring(iqueue, &मार्गः, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", मार्गः);
	dirp = opendir(मार्गः);
	यदि (dirp == रिक्त) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
	} अन्यथा {
		handle = handle_new(HANDLE_DIR, मार्गः, 0, 0, dirp);
		यदि (handle < 0) {
			closedir(dirp);
		} अन्यथा {
			send_handle(id, handle);
			स्थितिः = SSH2_FX_OK;
		}

	}
	यदि (स्थितिः != SSH2_FX_OK)
		send_स्थितिः(id, स्थितिः);
	मुक्त(मार्गः);
}

स्थिर शून्य
process_readdir(uint32_t id)
{
	DIR *dirp;
	संरचना dirent *dp;
	वर्ण *मार्गः;
	पूर्णाङ्क r, handle;

	यदि ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_गन्तव्यम्_name(handle), handle);
	dirp = handle_गन्तव्यम्_dir(handle);
	मार्गः = handle_गन्तव्यम्_name(handle);
	यदि (dirp == रिक्त || मार्गः == रिक्त) {
		send_स्थितिः(id, SSH2_FX_FAILURE);
	} अन्यथा {
		संरचना stat st;
		वर्ण *pathname;
		Stat *stats;
		पूर्णाङ्क nstats = 10, गणनम् = 0, i;

		stats = xcalloc(nstats, परिमाण(Stat));
		यावत् ((dp = readdir(dirp)) != रिक्त) {
			यदि (गणनम् >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, परिमाण(Stat));
			}
			xasprintf(&pathname, "%s%s%s", मार्गः,
			    वाक्यं_तुलय(मार्गः, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			मुक्त(pathname);
			यदि (r == -1)
				अनुवर्त;
			stat_गन्तव्यम्_attrib(&st, &(stats[गणनम्].attrib));
			stats[गणनम्].name = xstrdup(dp->d_name);
			stats[गणनम्].long_name = ls_file(dp->d_name, &st,
			    0, 0, रिक्त, रिक्त);
			गणनम्++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			यदि (गणनम् == 100)
				भङ्ग;
		}
		यदि (गणनम् > 0) {
			send_नामानि(id, गणनम्, stats);
			प्रति (i = 0; i < गणनम्; i++) {
				मुक्त(stats[i].name);
				मुक्त(stats[i].long_name);
			}
		} अन्यथा {
			send_स्थितिः(id, SSH2_FX_EOF);
		}
		मुक्त(stats);
	}
}

स्थिर शून्य
process_remove(uint32_t id)
{
	वर्ण *name;
	पूर्णाङ्क r, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_mkdir(uint32_t id)
{
	Attrib a;
	वर्ण *name;
	पूर्णाङ्क r, बहुलकम्, स्थितिः = SSH2_FX_FAILURE;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	बहुलकम् = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, बहुलकम्);
	r = mkdir(name, बहुलकम्);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_rmdir(uint32_t id)
{
	वर्ण *name;
	पूर्णाङ्क r, स्थितिः;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_realpath(uint32_t id)
{
	वर्ण resolvedname[PATH_MAX];
	वर्ण *मार्गः;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_cstring(iqueue, &मार्गः, रिक्त)) != 0)
		fatal_fr(r, "parse");

	यदि (मार्गः[0] == '\0') {
		मुक्त(मार्गः);
		मार्गः = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", मार्गः);
	यदि (sftp_realpath(मार्गः, resolvedname) == रिक्त) {
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
	} अन्यथा {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_नामानि(id, 1, &s);
	}
	मुक्त(मार्गः);
}

स्थिर शून्य
process_rename(uint32_t id)
{
	वर्ण *oldpath, *newpath;
	पूर्णाङ्क r, स्थितिः;
	संरचना stat sb;

	यदि ((r = sshbuf_get_cstring(iqueue, &oldpath, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	स्थितिः = SSH2_FX_FAILURE;
	यदि (lstat(oldpath, &sb) == -1)
		स्थितिः = errno_गन्तव्यम्_portable(errno);
	अन्यथा यदि (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		यदि (link(oldpath, newpath) == -1) {
			यदि (errno == EOPNOTSUPP || errno == ENOSYS
#यदि_परिभाषितम् EXDEV
			    || errno == EXDEV
#यदि_अन्तः
#यदि_परिभाषितम् LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#यदि_अन्तः
			    ) {
				संरचना stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				यदि (stat(newpath, &st) == -1) {
					यदि (rename(oldpath, newpath) == -1)
						स्थितिः =
						    errno_गन्तव्यम्_portable(errno);
					अन्यथा
						स्थितिः = SSH2_FX_OK;
				}
			} अन्यथा {
				स्थितिः = errno_गन्तव्यम्_portable(errno);
			}
		} अन्यथा यदि (unlink(oldpath) == -1) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} अन्यथा
			स्थितिः = SSH2_FX_OK;
	} अन्यथा यदि (stat(newpath, &sb) == -1) {
		यदि (rename(oldpath, newpath) == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
		अन्यथा
			स्थितिः = SSH2_FX_OK;
	}
	send_स्थितिः(id, स्थितिः);
	मुक्त(oldpath);
	मुक्त(newpath);
}

स्थिर शून्य
process_readlink(uint32_t id)
{
	पूर्णाङ्क r, len;
	वर्ण buf[PATH_MAX];
	वर्ण *मार्गः;

	यदि ((r = sshbuf_get_cstring(iqueue, &मार्गः, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", मार्गः);
	यदि ((len = readlink(मार्गः, buf, परिमाण(buf) - 1)) == -1)
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
	अन्यथा {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_नामानि(id, 1, &s);
	}
	मुक्त(मार्गः);
}

स्थिर शून्य
process_symlink(uint32_t id)
{
	वर्ण *oldpath, *newpath;
	पूर्णाङ्क r, स्थितिः;

	यदि ((r = sshbuf_get_cstring(iqueue, &oldpath, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(oldpath);
	मुक्त(newpath);
}

स्थिर शून्य
process_extended_posix_rename(uint32_t id)
{
	वर्ण *oldpath, *newpath;
	पूर्णाङ्क r, स्थितिः;

	यदि ((r = sshbuf_get_cstring(iqueue, &oldpath, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(oldpath);
	मुक्त(newpath);
}

स्थिर शून्य
process_extended_statvfs(uint32_t id)
{
	वर्ण *मार्गः;
	संरचना statvfs st;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_cstring(iqueue, &मार्गः, रिक्त)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", मार्गः);

	यदि (statvfs(मार्गः, &st) != 0)
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
	अन्यथा
		send_statvfs(id, &st);
	मुक्त(मार्गः);
}

स्थिर शून्य
process_extended_fstatvfs(uint32_t id)
{
	पूर्णाङ्क r, handle, fd;
	संरचना statvfs st;

	यदि ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_गन्तव्यम्_name(handle), handle);
	यदि ((fd = handle_गन्तव्यम्_fd(handle)) < 0) {
		send_स्थितिः(id, SSH2_FX_FAILURE);
		प्रत्यागम;
	}
	यदि (fstatvfs(fd, &st) != 0)
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
	अन्यथा
		send_statvfs(id, &st);
}

स्थिर शून्य
process_extended_hardlink(uint32_t id)
{
	वर्ण *oldpath, *newpath;
	पूर्णाङ्क r, स्थितिः;

	यदि ((r = sshbuf_get_cstring(iqueue, &oldpath, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	send_स्थितिः(id, स्थितिः);
	मुक्त(oldpath);
	मुक्त(newpath);
}

स्थिर शून्य
process_extended_fsync(uint32_t id)
{
	पूर्णाङ्क handle, fd, r, स्थितिः = SSH2_FX_OP_UNSUPPORTED;

	यदि ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_गन्तव्यम्_name(handle));
	यदि ((fd = handle_गन्तव्यम्_fd(handle)) < 0)
		स्थितिः = SSH2_FX_NO_SUCH_FILE;
	अन्यथा यदि (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		स्थितिः = (r == -1) ? errno_गन्तव्यम्_portable(errno) : SSH2_FX_OK;
	}
	send_स्थितिः(id, स्थितिः);
}

स्थिर शून्य
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	वर्ण *name;
	पूर्णाङ्क r, स्थितिः = SSH2_FX_OK;

	यदि ((r = sshbuf_get_cstring(iqueue, &name, रिक्त)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	यदि (a.flags & SSH2_FILEXFER_ATTR_आकार) {
		/* nonsensical for links */
		स्थितिः = SSH2_FX_BAD_सन्देशः;
		गच्छ बहिर्गमनम्;
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		वर्ण buf[64];
		time_t t = a.mtime;

		strftime(buf, परिमाण(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_गन्तव्यम्_ts(&a), AT_SYMLINK_NOFOLLOW);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
	यदि (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		यदि (r == -1)
			स्थितिः = errno_गन्तव्यम्_portable(errno);
	}
 बहिर्गमनम्:
	send_स्थितिः(id, स्थितिः);
	मुक्त(name);
}

स्थिर शून्य
process_extended_limits(uint32_t id)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;
	uint64_t nfiles = 0;
#यदि defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	संरचना rlimit rlim;
#यदि_अन्तः

	debug("request %u: limits", id);

#यदि defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	यदि (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#यदि_अन्तः

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED_प्रत्युत्तरम्)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(सन्देशः, SFTP_MAX_सन्देशः_दीर्घता)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(सन्देशः, SFTP_MAX_READ_दीर्घता)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(सन्देशः, SFTP_MAX_सन्देशः_दीर्घता - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(सन्देशः, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
process_extended_expand(uint32_t id)
{
	वर्ण cwd[PATH_MAX], resolvedname[PATH_MAX];
	वर्ण *मार्गः, *npath;
	पूर्णाङ्क r;
	Stat s;

	यदि ((r = sshbuf_get_cstring(iqueue, &मार्गः, रिक्त)) != 0)
		fatal_fr(r, "parse");
	यदि (getcwd(cwd, परिमाण(cwd)) == रिक्त) {
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
		गच्छ बहिर्गमनम्;
	}

	debug3("request %u: expand, original \"%s\"", id, मार्गः);
	यदि (मार्गः[0] == '\0') {
		/* empty path */
		मुक्त(मार्गः);
		मार्गः = xstrdup(".");
	} अन्यथा यदि (*मार्गः == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		यदि (वाक्यं_तुलय(मार्गः, "~") == 0) {
			मुक्त(मार्गः);
			मार्गः = xstrdup(cwd);
		} अन्यथा यदि (वाक्ये_तुलय(मार्गः, "~/", 2) == 0) {
			npath = xstrdup(मार्गः + 2);
			मुक्त(मार्गः);
			xasprintf(&मार्गः, "%s/%s", cwd, npath);
			मुक्त(npath);
		} अन्यथा {
			/* ~user expansions */
			यदि (tilde_expand(मार्गः, pw->pw_uid, &npath) != 0) {
				send_स्थितिः_errmsg(id,
				    errno_गन्तव्यम्_portable(ENOENT), "no such user");
				गच्छ बहिर्गमनम्;
			}
			मुक्त(मार्गः);
			मार्गः = npath;
		}
	} अन्यथा यदि (*मार्गः != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, मार्गः);
		मुक्त(मार्गः);
		मार्गः = npath;
	}
	verbose("expand \"%s\"", मार्गः);
	यदि (sftp_realpath(मार्गः, resolvedname) == रिक्त) {
		send_स्थितिः(id, errno_गन्तव्यम्_portable(errno));
		गच्छ बहिर्गमनम्;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_नामानि(id, 1, &s);
 बहिर्गमनम्:
	मुक्त(मार्गः);
}

स्थिर शून्य
process_extended_copy_दत्त(uint32_t id)
{
	u_char buf[64*1024];
	पूर्णाङ्क read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	पूर्णाङ्क r, copy_until_eof, स्थितिः = SSH2_FX_OP_UNSUPPORTED;
	आकार_t ret;
	संरचना stat st_read, st_write;

	यदि ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_गन्तव्यम्_name(read_handle), read_handle,
	    (अचिह्नित दीर्घ दीर्घ)read_off, (अचिह्नित दीर्घ दीर्घ)read_len,
	    handle_गन्तव्यम्_name(write_handle), write_handle,
	    (अचिह्नित दीर्घ दीर्घ)write_off);

	/* For read length of 0, we read until EOF. */
	यदि (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} अन्यथा
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_गन्तव्यम्_fd(read_handle);
	write_fd = handle_गन्तव्यम्_fd(write_handle);
	यदि (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		स्थितिः = errno_गन्तव्यम्_portable(EBADF);
		गच्छ बहिर्गमनम्;
	}
	यदि (fstat(read_fd, &st_read) != 0) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("fstat read_fd failed: %s", strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि (fstat(write_fd, &st_write) != 0) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("fstat write_fd failed: %s", strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यदि (read_handle == write_handle ||
	    !वाक्यं_तुलय(handle_गन्तव्यम्_name(read_handle), handle_गन्तव्यम्_name(write_handle)) ||
	    (st_read.st_dev != 0 && st_read.st_ino != 0 &&
	    st_read.st_dev == st_write.st_dev &&
	    st_read.st_ino == st_write.st_ino)) {
		error_f("refusing to read/write same file: "
		    "read \"%s\" dev %lu ino %lu, write \"%s\" dev %lu ino %lu",
		    handle_गन्तव्यम्_name(read_handle),
		    (u_long)st_read.st_dev, (u_long)st_read.st_ino,
		    handle_गन्तव्यम्_name(write_handle),
		    (u_long)st_write.st_dev, (u_long)st_write.st_ino);
		स्थितिः = SSH2_FX_FAILURE;
		गच्छ बहिर्गमनम्;
	}

	यदि (lseek(read_fd, read_off, SEEK_SET) < 0) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("read_seek failed");
		गच्छ बहिर्गमनम्;
	}

	यदि ((handle_गन्तव्यम्_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, SEEK_SET) < 0) {
		स्थितिः = errno_गन्तव्यम्_portable(errno);
		error_f("write_seek failed");
		गच्छ बहिर्गमनम्;
	}

	/* Process the request in chunks. */
	यावत् (read_len > 0 || copy_until_eof) {
		len = MINIMUM(परिमाण(buf), read_len);
		read_len -= len;

		ret = atomicio(पठ, read_fd, buf, len);
		यदि (ret == 0 && errno == EPIPE) {
			स्थितिः = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			भङ्ग;
		} अन्यथा यदि (ret == 0) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
			error_f("read failed: %s", strerror(errno));
			भङ्ग;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		यदि (ret != len) {
			स्थितिः = errno_गन्तव्यम्_portable(errno);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (अचिह्नित दीर्घ दीर्घ)ret, (अचिह्नित दीर्घ दीर्घ)len,
			    strerror(errno));
			भङ्ग;
		}
		handle_update_write(write_handle, len);
	}

	यदि (read_len == 0)
		स्थितिः = SSH2_FX_OK;

 बहिर्गमनम्:
	send_स्थितिः(id, स्थितिः);
}

स्थिर शून्य
process_extended_home_directory(uint32_t id)
{
	वर्ण *username;
	संरचना passwd *user_pw;
	पूर्णाङ्क r;
	Stat s;

	यदि ((r = sshbuf_get_cstring(iqueue, &username, रिक्त)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	यदि (username[0] == '\0') {
		user_pw = pw;
	} अन्यथा यदि ((user_pw = getpwnam(username)) == रिक्त) {
		send_स्थितिः(id, SSH2_FX_FAILURE);
		गच्छ बहिर्गमनम्;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_नामानि(id, 1, &s);
 बहिर्गमनम्:
	मुक्त(username);
}

स्थिर शून्य
process_extended_get_users_groups_by_id(uint32_t id)
{
	संरचना passwd *user_pw;
	संरचना गणः *gr;
	संरचना sshbuf *uids, *gids, *usernames, *groupnames, *सन्देशः;
	पूर्णाङ्क r;
	u_int n, nusers = 0, ngroups = 0;
	ध्रुव वर्ण *name;

	यदि ((usernames = sshbuf_new()) == रिक्त ||
	    (groupnames = sshbuf_new()) == रिक्त ||
	    (सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	यावत् (sshbuf_len(uids) != 0) {
		यदि ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == रिक्त ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		यदि ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	यावत् (sshbuf_len(gids) != 0) {
		यदि ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == रिक्त ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		यदि ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED_प्रत्युत्तरम्)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(सन्देशः);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
process_extended(uint32_t id)
{
	वर्ण *request;
	पूर्णाङ्क r;
	ध्रुव संरचना sftp_handler *exthand;

	यदि ((r = sshbuf_get_cstring(iqueue, &request, रिक्त)) != 0)
		fatal_fr(r, "parse");
	यदि ((exthand = extended_handler_byname(request)) == रिक्त) {
		error("Unknown extended request \"%.100s\"", request);
		send_स्थितिः(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} अन्यथा {
		यदि (!request_permitted(exthand))
			send_स्थितिः(id, SSH2_FX_PERMISSION_DENIED);
		अन्यथा
			exthand->handler(id);
	}
	मुक्त(request);
}

/* stolen from ssh-agent */

स्थिर शून्य
process(शून्य)
{
	u_int सन्देशः_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	ध्रुव u_char *cp;
	पूर्णाङ्क i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	यदि (buf_len < 5)
		प्रत्यागम;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	सन्देशः_len = get_u32(cp);
	यदि (सन्देशः_len > SFTP_MAX_सन्देशः_दीर्घता) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	यदि (buf_len < सन्देशः_len + 4)
		प्रत्यागम;
	यदि ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	यदि ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	विकल्प (type) {
	पक्ष SSH2_FXP_INIT:
		process_init();
		init_समाप्तम् = 1;
		भङ्ग;
	पक्ष SSH2_FXP_EXTENDED:
		यदि (!init_समाप्तम्)
			fatal("Received extended request before init");
		यदि ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		भङ्ग;
	स्वभाव:
		यदि (!init_समाप्तम्)
			fatal("Received %u request before init", type);
		यदि ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		प्रति (i = 0; handlers[i].handler != रिक्त; i++) {
			यदि (type == handlers[i].type) {
				यदि (!request_permitted(&handlers[i])) {
					send_स्थितिः(id,
					    SSH2_FX_PERMISSION_DENIED);
				} अन्यथा {
					handlers[i].handler(id);
				}
				भङ्ग;
			}
		}
		यदि (handlers[i].handler == रिक्त)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	यदि (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	यदि (सन्देशः_len < consumed) {
		error("msg_len %u < consumed %u", सन्देशः_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	यदि (सन्देशः_len > consumed &&
	    (r = sshbuf_consume(iqueue, सन्देशः_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
शून्य
sftp_server_cleanup_exit(पूर्णाङ्क i)
{
	यदि (pw != रिक्त && client_addr != रिक्त) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

स्थिर शून्य
sftp_server_usage(शून्य)
{
	बाह्य वर्ण *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	निर्गच्छ(1);
}

पूर्णाङ्क
sftp_server_main(पूर्णाङ्क argc, वर्ण **argv, संरचना passwd *user_pw)
{
	पूर्णाङ्क i, r, अन्तर्, बहिर्गमनम्, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	वर्ण *cp, *homedir = रिक्त, uidstr[32], buf[4*4096];
	दीर्घ आवरणम्;

	बाह्य वर्ण *optarg;
	बाह्य वर्ण *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	यावत् (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		विकल्प (ch) {
		पक्ष 'Q':
			यदि (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				निर्गच्छ(1);
			}
			प्रति (i = 0; handlers[i].handler != रिक्त; i++)
				प्रारूप_लिख("%s\n", handlers[i].name);
			प्रति (i = 0; extended_handlers[i].handler != रिक्त; i++)
				प्रारूप_लिख("%s\n", extended_handlers[i].name);
			निर्गच्छ(0);
			भङ्ग;
		पक्ष 'R':
			readonly = 1;
			भङ्ग;
		पक्ष 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			भङ्ग;
		पक्ष 'e':
			log_stderr = 1;
			भङ्ग;
		पक्ष 'l':
			log_level = log_level_सङ्ख्या(optarg);
			यदि (log_level == SYSLOG_LEVEL_NOT_समुच्चयः)
				error("Invalid log level \"%s\"", optarg);
			भङ्ग;
		पक्ष 'f':
			log_facility = log_facility_सङ्ख्या(optarg);
			यदि (log_facility == SYSLOG_FACILITY_NOT_समुच्चयः)
				error("Invalid log facility \"%s\"", optarg);
			भङ्ग;
		पक्ष 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, परिमाण(uidstr), "%llu",
			    (अचिह्नित दीर्घ दीर्घ)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (वर्ण *)रिक्त);
			मुक्त(cp);
			भङ्ग;
		पक्ष 'p':
			यदि (request_allowlist != रिक्त)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			भङ्ग;
		पक्ष 'P':
			यदि (request_denylist != रिक्त)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			भङ्ग;
		पक्ष 'u':
			errno = 0;
			आवरणम् = strtol(optarg, &cp, 8);
			यदि (आवरणम् < 0 || आवरणम् > 0777 || *cp != '\0' ||
			    cp == optarg || (आवरणम् == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(शून्य)umask((बहुलकम्_t)आवरणम्);
			भङ्ग;
		पक्ष 'h':
		स्वभाव:
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

	यदि ((cp = getenv("SSH_CONNECTION")) != रिक्त) {
		client_addr = xstrdup(cp);
		यदि ((cp = strchr(client_addr, ' ')) == रिक्त) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} अन्यथा
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	अन्तर् = STDIN_FILENO;
	बहिर्गमनम् = STDOUT_FILENO;

#यदि_परिभाषितम् HAVE_CYGWIN
	setmode(अन्तर्, O_द्विमान);
	setmode(बहिर्गमनम्, O_द्विमान);
#यदि_अन्तः

	यदि ((iqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((oqueue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यदि (homedir != रिक्त) {
		यदि (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	प्रति (;;) {
		संरचना pollfd pfd[2];

		स्मृतिं_पूरय(pfd, 0, परिमाण pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		यदि ((r = sshbuf_check_reserve(iqueue, परिमाण(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_सन्देशः_दीर्घता)) == 0) {
			pfd[0].fd = अन्तर्;
			pfd[0].events = POLLIN;
		}
		अन्यथा यदि (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		यदि (olen > 0) {
			pfd[1].fd = बहिर्गमनम्;
			pfd[1].events = POLLOUT;
		}

		यदि (poll(pfd, 2, -1) == -1) {
			यदि (errno == EINTR)
				अनुवर्त;
			error("poll: %s", strerror(errno));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		यदि (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = पठ(अन्तर्, buf, परिमाण buf);
			यदि (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} अन्यथा यदि (len == -1) {
				यदि (errno != EAGAIN && errno != EINTR) {
					error("read: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} अन्यथा यदि ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		यदि (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = लिख(बहिर्गमनम्, sshbuf_ptr(oqueue), olen);
			यदि (len == 0 || (len == -1 && errno == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} अन्यथा यदि (len == -1) {
				sftp_server_cleanup_exit(1);
				यदि (errno != EAGAIN && errno != EINTR) {
					error("write: %s", strerror(errno));
					sftp_server_cleanup_exit(1);
				}
			} अन्यथा यदि ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_सन्देशः_दीर्घता);
		यदि (r == 0)
			process();
		अन्यथा यदि (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");
	}
}
