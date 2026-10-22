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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/resource.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/statvfs.h>

#समावेश <dirent.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <poll.h>
#समावेश <pwd.h>
#समावेश <grp.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <stdarg.h>

#समावेश "atomicio.h"
#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "match.h"
#समावेश "uidswap.h"

#समावेश "sftp.h"
#समावेश "sftp-common.h"

अक्षर *sftp_realpath(स्थिर अक्षर *, अक्षर *); /* sftp-realpath.c */

/* Maximum data read that we are willing to accept */
#घोषणा SFTP_MAX_READ_लंबाई (SFTP_MAX_संदेश_लंबाई - 1024)

/* Our verbosity */
अटल LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
अटल काष्ठा passwd *pw = शून्य;
अटल अक्षर *client_addr = शून्य;

/* input and output queue */
काष्ठा sshbuf *iqueue;
काष्ठा sshbuf *oqueue;

/* Version of client */
अटल u_int version;

/* SSH2_FXP_INIT received */
अटल पूर्णांक init_done;

/* Disable writes */
अटल पूर्णांक readonly;

/* Requests that are allowed/denied */
अटल अक्षर *request_allowlist, *request_denylist;

/* portable attributes, etc. */
प्रकार काष्ठा Stat Stat;

काष्ठा Stat {
	अक्षर *name;
	अक्षर *long_name;
	Attrib attrib;
};

/* Packet handlers */
अटल व्योम process_open(uint32_t id);
अटल व्योम process_close(uint32_t id);
अटल व्योम process_read(uint32_t id);
अटल व्योम process_write(uint32_t id);
अटल व्योम process_stat(uint32_t id);
अटल व्योम process_lstat(uint32_t id);
अटल व्योम process_fstat(uint32_t id);
अटल व्योम process_setstat(uint32_t id);
अटल व्योम process_fsetstat(uint32_t id);
अटल व्योम process_opendir(uint32_t id);
अटल व्योम process_readdir(uint32_t id);
अटल व्योम process_remove(uint32_t id);
अटल व्योम process_mkdir(uint32_t id);
अटल व्योम process_rmdir(uint32_t id);
अटल व्योम process_realpath(uint32_t id);
अटल व्योम process_rename(uint32_t id);
अटल व्योम process_readlink(uint32_t id);
अटल व्योम process_symlink(uint32_t id);
अटल व्योम process_extended_posix_rename(uint32_t id);
अटल व्योम process_extended_statvfs(uint32_t id);
अटल व्योम process_extended_fstatvfs(uint32_t id);
अटल व्योम process_extended_hardlink(uint32_t id);
अटल व्योम process_extended_fsync(uint32_t id);
अटल व्योम process_extended_lsetstat(uint32_t id);
अटल व्योम process_extended_limits(uint32_t id);
अटल व्योम process_extended_expand(uint32_t id);
अटल व्योम process_extended_copy_तथ्य(uint32_t id);
अटल व्योम process_extended_home_directory(uint32_t id);
अटल व्योम process_extended_get_users_groups_by_id(uint32_t id);
अटल व्योम process_extended(uint32_t id);

काष्ठा sftp_handler {
	स्थिर अक्षर *name;	/* user-visible name for fine-grained perms */
	स्थिर अक्षर *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	व्योम (*handler)(uint32_t);
	पूर्णांक does_write;		/* if nonzero, banned for readonly mode */
};

अटल स्थिर काष्ठा sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", शून्य, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", शून्य, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", शून्य, SSH2_FXP_READ, process_read, 0 },
	{ "write", शून्य, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", शून्य, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", शून्य, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", शून्य, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", शून्य, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", शून्य, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", शून्य, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", शून्य, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", शून्य, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", शून्य, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", शून्य, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", शून्य, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", शून्य, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", शून्य, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", शून्य, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ शून्य, शून्य, 0, शून्य, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
अटल स्थिर काष्ठा sftp_handler extended_handlers[] = {
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
	{ "copy-data", "copy-data", 0, process_extended_copy_तथ्य, 1 },
	{ "home-directory", "home-directory", 0,
	    process_extended_home_directory, 0 },
	{ "users-groups-by-id", "users-groups-by-id@openssh.com", 0,
	    process_extended_get_users_groups_by_id, 0 },
	{ शून्य, शून्य, 0, शून्य, 0 }
};

अटल स्थिर काष्ठा sftp_handler *
extended_handler_byname(स्थिर अक्षर *name)
{
	पूर्णांक i;

	क्रम (i = 0; extended_handlers[i].handler != शून्य; i++) {
		अगर (म_भेद(name, extended_handlers[i].ext_name) == 0)
			वापस &extended_handlers[i];
	}
	वापस शून्य;
}

अटल पूर्णांक
request_permitted(स्थिर काष्ठा sftp_handler *h)
{
	अक्षर *परिणाम;

	अगर (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		वापस 0;
	}
	अगर (request_denylist != शून्य &&
	    ((परिणाम = match_list(h->name, request_denylist, शून्य))) != शून्य) {
		मुक्त(परिणाम);
		verbose("Refusing denylisted %s request", h->name);
		वापस 0;
	}
	अगर (request_allowlist != शून्य &&
	    ((परिणाम = match_list(h->name, request_allowlist, शून्य))) != शून्य) {
		मुक्त(परिणाम);
		debug2("Permitting allowlisted %s request", h->name);
		वापस 1;
	}
	अगर (request_allowlist != शून्य) {
		verbose("Refusing non-allowlisted %s request", h->name);
		वापस 0;
	}
	वापस 1;
}

अटल पूर्णांक
errno_to_portable(पूर्णांक unixerrno)
{
	पूर्णांक ret = 0;

	चयन (unixerrno) {
	हाल 0:
		ret = SSH2_FX_OK;
		अवरोध;
	हाल ENOENT:
	हाल ENOTDIR:
	हाल EBADF:
	हाल ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		अवरोध;
	हाल EPERM:
	हाल EACCES:
	हाल EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		अवरोध;
	हाल ENAMETOOLONG:
	हाल EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		अवरोध;
	हाल ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		अवरोध;
	शेष:
		ret = SSH2_FX_FAILURE;
		अवरोध;
	}
	वापस ret;
}

अटल पूर्णांक
flags_from_portable(पूर्णांक pflags)
{
	पूर्णांक flags = 0;

	अगर ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} अन्यथा अगर (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} अन्यथा अगर (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	अगर (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	अगर (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	अगर (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	अगर (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	वापस flags;
}

अटल स्थिर अक्षर *
string_from_portable(पूर्णांक pflags)
{
	अटल अक्षर ret[128];

	*ret = '\0';

#घोषणा PAPPEND(str)	{				\
		अगर (*ret != '\0')			\
			strlcat(ret, ",", माप(ret));	\
		strlcat(ret, str, माप(ret));		\
	}

	अगर (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	अगर (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	अगर (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	अगर (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	अगर (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	अगर (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	वापस ret;
}

/* handle handles */

प्रकार काष्ठा Handle Handle;
काष्ठा Handle {
	पूर्णांक use;
	सूची *dirp;
	पूर्णांक fd;
	पूर्णांक flags;
	अक्षर *name;
	uint64_t bytes_read, bytes_write;
	पूर्णांक अग्र_unused;
};

क्रमागत {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

अटल Handle *handles = शून्य;
अटल u_int अंक_handles = 0;
अटल पूर्णांक first_unused_handle = -1;

अटल व्योम handle_unused(पूर्णांक i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].अग्र_unused = first_unused_handle;
	first_unused_handle = i;
}

अटल पूर्णांक
handle_new(पूर्णांक use, स्थिर अक्षर *name, पूर्णांक fd, पूर्णांक flags, सूची *dirp)
{
	पूर्णांक i;

	अगर (first_unused_handle == -1) {
		अगर (अंक_handles + 1 <= अंक_handles)
			वापस -1;
		अंक_handles++;
		handles = xreallocarray(handles, अंक_handles, माप(Handle));
		handle_unused(अंक_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].अग्र_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	वापस i;
}

अटल पूर्णांक
handle_is_ok(पूर्णांक i, पूर्णांक type)
{
	वापस i >= 0 && (u_int)i < अंक_handles && handles[i].use == type;
}

अटल पूर्णांक
handle_to_string(पूर्णांक handle, u_char **stringp, पूर्णांक *hlenp)
{
	अगर (stringp == शून्य || hlenp == शून्य)
		वापस -1;
	*stringp = xmalloc(माप(int32_t));
	put_u32(*stringp, handle);
	*hlenp = माप(int32_t);
	वापस 0;
}

अटल पूर्णांक
handle_from_string(स्थिर u_char *handle, u_int hlen)
{
	पूर्णांक val;

	अगर (hlen != माप(int32_t))
		वापस -1;
	val = get_u32(handle);
	अगर (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		वापस val;
	वापस -1;
}

अटल अक्षर *
handle_to_name(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		वापस handles[handle].name;
	वापस शून्य;
}

अटल सूची *
handle_to_dir(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_DIR))
		वापस handles[handle].dirp;
	वापस शून्य;
}

अटल पूर्णांक
handle_to_fd(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_FILE))
		वापस handles[handle].fd;
	वापस -1;
}

अटल पूर्णांक
handle_to_flags(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_FILE))
		वापस handles[handle].flags;
	वापस 0;
}

अटल व्योम
handle_update_read(पूर्णांक handle, ssize_t bytes)
{
	अगर (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

अटल व्योम
handle_update_write(पूर्णांक handle, ssize_t bytes)
{
	अगर (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

अटल uint64_t
handle_bytes_read(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_FILE))
		वापस (handles[handle].bytes_read);
	वापस 0;
}

अटल uint64_t
handle_bytes_write(पूर्णांक handle)
{
	अगर (handle_is_ok(handle, HANDLE_FILE))
		वापस (handles[handle].bytes_write);
	वापस 0;
}

अटल पूर्णांक
handle_close(पूर्णांक handle)
{
	पूर्णांक ret = -1;

	अगर (handle_is_ok(handle, HANDLE_FILE)) {
		ret = बंद(handles[handle].fd);
		मुक्त(handles[handle].name);
		handle_unused(handle);
	} अन्यथा अगर (handle_is_ok(handle, HANDLE_DIR)) {
		ret = बंद_सूची(handles[handle].dirp);
		मुक्त(handles[handle].name);
		handle_unused(handle);
	} अन्यथा {
		त्रुटि_सं = ENOENT;
	}
	वापस ret;
}

अटल व्योम
handle_log_close(पूर्णांक handle, अक्षर *emsg)
{
	अगर (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == शून्य ? "" : emsg, emsg == शून्य ? "" : " ",
		    handle_to_name(handle),
		    (अचिन्हित दीर्घ दीर्घ)handle_bytes_read(handle),
		    (अचिन्हित दीर्घ दीर्घ)handle_bytes_write(handle));
	} अन्यथा {
		logit("%s%sclosedir \"%s\"",
		    emsg == शून्य ? "" : emsg, emsg == शून्य ? "" : " ",
		    handle_to_name(handle));
	}
}

अटल व्योम
handle_log_exit(व्योम)
{
	u_int i;

	क्रम (i = 0; i < अंक_handles; i++)
		अगर (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

अटल पूर्णांक
get_handle(काष्ठा sshbuf *queue, पूर्णांक *hp)
{
	u_char *handle;
	पूर्णांक r;
	माप_प्रकार hlen;

	*hp = -1;
	अगर ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		वापस r;
	अगर (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	मुक्त(handle);
	वापस 0;
}

/* send replies */

अटल व्योम
send_संदेश(काष्ठा sshbuf *m)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_reset(m);
}

अटल स्थिर अक्षर *
status_to_message(uint32_t status)
{
	अटल स्थिर अक्षर * स्थिर status_messages[] = {
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
	वापस (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

अटल व्योम
send_status_errmsg(uint32_t id, uint32_t status, स्थिर अक्षर *errmsg)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	debug3("request %u: sent status %u", id, status);
	अगर (log_level > SYSLOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, status)) != 0)
		fatal_fr(r, "compose");
	अगर (version >= 3) {
		अगर ((r = sshbuf_put_cstring(संदेश, errmsg == शून्य ?
		    status_to_message(status) : errmsg)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश, "")) != 0)
			fatal_fr(r, "compose message");
	}
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
send_status(uint32_t id, uint32_t status)
{
	send_status_errmsg(id, status, शून्य);
}

अटल व्योम
send_तथ्य_or_handle(अक्षर type, uint32_t id, स्थिर u_char *तथ्य, पूर्णांक dlen)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, तथ्य, dlen)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
send_तथ्य(uint32_t id, स्थिर u_char *तथ्य, पूर्णांक dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_तथ्य_or_handle(SSH2_FXP_तथ्य, id, तथ्य, dlen);
}

अटल व्योम
send_handle(uint32_t id, पूर्णांक handle)
{
	u_char *string;
	पूर्णांक hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle %d", id, handle);
	send_तथ्य_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	मुक्त(string);
}

अटल व्योम
send_names(uint32_t id, पूर्णांक गिनती, स्थिर Stat *stats)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक i, r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, गिनती)) != 0)
		fatal_fr(r, "compose");
	debug("request %u: sent names count %d", id, गिनती);
	क्रम (i = 0; i < गिनती; i++) {
		अगर ((r = sshbuf_put_cstring(संदेश, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(संदेश, &stats[i].attrib)) != 0)
			fatal_fr(r, "compose filenames/attrib");
	}
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
send_attrib(uint32_t id, स्थिर Attrib *a)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
send_statvfs(uint32_t id, काष्ठा statvfs *st)
{
	काष्ठा sshbuf *संदेश;
	uint64_t flag;
	पूर्णांक r;

	flag = (st->f_flag & ST_RDONLY) ? SSH2_FXE_STATVFS_ST_RDONLY : 0;
	flag |= (st->f_flag & ST_NOSUID) ? SSH2_FXE_STATVFS_ST_NOSUID : 0;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_bsize)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_frsize)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_blocks)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_bfree)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_bavail)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_files)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_ffree)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_favail)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, FSID_TO_ULONG(st->f_fsid))) != 0 ||
	    (r = sshbuf_put_u64(संदेश, flag)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, st->f_namemax)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

/*
 * Prepare SSH2_FXP_VERSION extension advertisement for a single extension.
 * The extension is checked for permission prior to advertisement.
 */
अटल पूर्णांक
compose_extension(काष्ठा sshbuf *संदेश, स्थिर अक्षर *name, स्थिर अक्षर *ver)
{
	पूर्णांक r;
	स्थिर काष्ठा sftp_handler *exthnd;

	अगर ((exthnd = extended_handler_byname(name)) == शून्य)
		fatal_f("internal error: no handler for %s", name);
	अगर (!request_permitted(exthnd)) {
		debug2_f("refusing to advertise disallowed extension %s", name);
		वापस 0;
	}
	अगर ((r = sshbuf_put_cstring(संदेश, name)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, ver)) != 0)
		fatal_fr(r, "compose %s", name);
	वापस 0;
}

/* parse incoming */

अटल व्योम
process_init(व्योम)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal_fr(r, "parse");
	verbose("received client version %u", version);
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "compose");

	 /* extension advertisements */
	compose_extension(संदेश, "posix-rename@openssh.com", "1");
	compose_extension(संदेश, "statvfs@openssh.com", "2");
	compose_extension(संदेश, "fstatvfs@openssh.com", "2");
	compose_extension(संदेश, "hardlink@openssh.com", "1");
	compose_extension(संदेश, "fsync@openssh.com", "1");
	compose_extension(संदेश, "lsetstat@openssh.com", "1");
	compose_extension(संदेश, "limits@openssh.com", "1");
	compose_extension(संदेश, "expand-path@openssh.com", "1");
	compose_extension(संदेश, "copy-data", "1");
	compose_extension(संदेश, "home-directory", "1");
	compose_extension(संदेश, "users-groups-by-id@openssh.com", "1");

	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	अक्षर *name;
	पूर्णांक r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	अगर (readonly &&
	    ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} अन्यथा {
		fd = खोलो(name, flags, mode);
		अगर (fd == -1) {
			status = errno_to_portable(त्रुटि_सं);
		} अन्यथा {
			handle = handle_new(HANDLE_FILE, name, fd, flags, शून्य);
			अगर (handle < 0) {
				बंद(fd);
			} अन्यथा {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	अगर (status != SSH2_FX_OK)
		send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_close(uint32_t id)
{
	पूर्णांक r, handle, ret, status = SSH2_FX_FAILURE;

	अगर ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, शून्य);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
}

अटल व्योम
process_read(uint32_t id)
{
	अटल u_char *buf;
	अटल माप_प्रकार buflen;
	uint32_t len;
	पूर्णांक r, handle, fd, ret, status = SSH2_FX_FAILURE;
	uint64_t off;

	अगर ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: read \"%s\" (handle %d) off %llu len %u",
	    id, handle_to_name(handle), handle, (अचिन्हित दीर्घ दीर्घ)off, len);
	अगर ((fd = handle_to_fd(handle)) == -1)
		जाओ out;
	अगर (len > SFTP_MAX_READ_लंबाई) {
		debug2("read change len %u to %u", len, SFTP_MAX_READ_लंबाई);
		len = SFTP_MAX_READ_लंबाई;
	}
	अगर (len > buflen) {
		debug3_f("allocate %zu => %u", buflen, len);
		अगर ((buf = पुनः_स्मृति(buf, len)) == शून्य)
			fatal_f("realloc failed");
		buflen = len;
	}
	अगर (lseek(fd, off, शुरू_से) == -1) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("seek \"%.100s\": %s", handle_to_name(handle),
		    म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (len == 0) {
		/* weird, but not strictly disallowed */
		ret = 0;
	} अन्यथा अगर ((ret = पढ़ो(fd, buf, len)) == -1) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("read \"%.100s\": %s", handle_to_name(handle),
		    म_त्रुटि(त्रुटि_सं));
		जाओ out;
	} अन्यथा अगर (ret == 0) {
		status = SSH2_FX_EOF;
		जाओ out;
	}
	send_तथ्य(id, buf, ret);
	handle_update_read(handle, ret);
	/* success */
	status = SSH2_FX_OK;
 out:
	अगर (status != SSH2_FX_OK)
		send_status(id, status);
}

अटल व्योम
process_write(uint32_t id)
{
	uint64_t off;
	माप_प्रकार len;
	पूर्णांक r, handle, fd, ret, status;
	u_char *तथ्य;

	अगर ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &तथ्य, &len)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (अचिन्हित दीर्घ दीर्घ)off, len);
	fd = handle_to_fd(handle);

	अगर (fd < 0)
		status = SSH2_FX_FAILURE;
	अन्यथा {
		अगर (!(handle_to_flags(handle) & O_APPEND) &&
		    lseek(fd, off, शुरू_से) == -1) {
			status = errno_to_portable(त्रुटि_सं);
			error_f("seek \"%.100s\": %s", handle_to_name(handle),
			    म_त्रुटि(त्रुटि_सं));
		} अन्यथा {
/* XXX ATOMICIO ? */
			ret = ग_लिखो(fd, तथ्य, len);
			अगर (ret == -1) {
				status = errno_to_portable(त्रुटि_सं);
				error_f("write \"%.100s\": %s",
				    handle_to_name(handle), म_त्रुटि(त्रुटि_सं));
			} अन्यथा अगर ((माप_प्रकार)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} अन्यथा {
				debug2_f("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	मुक्त(तथ्य);
}

अटल व्योम
process_do_stat(uint32_t id, पूर्णांक do_lstat)
{
	Attrib a;
	काष्ठा stat st;
	अक्षर *name;
	पूर्णांक r, status = SSH2_FX_FAILURE;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	अगर (r == -1) {
		status = errno_to_portable(त्रुटि_सं);
	} अन्यथा {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	अगर (status != SSH2_FX_OK)
		send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

अटल व्योम
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

अटल व्योम
process_fstat(uint32_t id)
{
	Attrib a;
	काष्ठा stat st;
	पूर्णांक fd, r, handle, status = SSH2_FX_FAILURE;

	अगर ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	अगर (fd >= 0) {
		r = ख_स्थिति(fd, &st);
		अगर (r == -1) {
			status = errno_to_portable(त्रुटि_सं);
		} अन्यथा {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	अगर (status != SSH2_FX_OK)
		send_status(id, status);
}

अटल काष्ठा timeval *
attrib_to_tv(स्थिर Attrib *a)
{
	अटल काष्ठा timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	वापस tv;
}

अटल काष्ठा timespec *
attrib_to_ts(स्थिर Attrib *a)
{
	अटल काष्ठा timespec ts[2];

	ts[0].tv_sec = a->atime;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = a->mtime;
	ts[1].tv_nsec = 0;
	वापस ts;
}

अटल व्योम
process_setstat(uint32_t id)
{
	Attrib a;
	अक्षर *name;
	पूर्णांक r, status = SSH2_FX_OK;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: setstat name \"%s\"", id, name);
	अगर (a.flags & SSH2_FILEXFER_ATTR_आकार) {
		logit("set \"%s\" size %llu",
		    name, (अचिन्हित दीर्घ दीर्घ)a.आकार);
		r = truncate(name, a.आकार);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		अक्षर buf[64];
		समय_प्रकार t = a.mtime;

		स_माला(buf, माप(buf), "%Y%m%d-%H:%M:%S",
		    स_स्थानीय(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_fsetstat(uint32_t id)
{
	Attrib a;
	पूर्णांक handle, fd, r;
	पूर्णांक status = SSH2_FX_OK;

	अगर ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	अगर (fd < 0)
		status = SSH2_FX_FAILURE;
	अन्यथा {
		अक्षर *name = handle_to_name(handle);

		अगर (a.flags & SSH2_FILEXFER_ATTR_आकार) {
			logit("set \"%s\" size %llu",
			    name, (अचिन्हित दीर्घ दीर्घ)a.आकार);
			r = ftruncate(fd, a.आकार);
			अगर (r == -1)
				status = errno_to_portable(त्रुटि_सं);
		}
		अगर (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#अगर_घोषित HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#अन्यथा
			r = chmod(name, a.perm & 07777);
#पूर्ण_अगर
			अगर (r == -1)
				status = errno_to_portable(त्रुटि_सं);
		}
		अगर (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			अक्षर buf[64];
			समय_प्रकार t = a.mtime;

			स_माला(buf, माप(buf), "%Y%m%d-%H:%M:%S",
			    स_स्थानीय(&t));
			logit("set \"%s\" modtime %s", name, buf);
#अगर_घोषित HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#अन्यथा
			r = utimes(name, attrib_to_tv(&a));
#पूर्ण_अगर
			अगर (r == -1)
				status = errno_to_portable(त्रुटि_सं);
		}
		अगर (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#अगर_घोषित HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#अन्यथा
			r = chown(name, a.uid, a.gid);
#पूर्ण_अगर
			अगर (r == -1)
				status = errno_to_portable(त्रुटि_सं);
		}
	}
	send_status(id, status);
}

अटल व्योम
process_opendir(uint32_t id)
{
	सूची *dirp = शून्य;
	अक्षर *path;
	पूर्णांक r, handle, status = SSH2_FX_FAILURE;

	अगर ((r = sshbuf_get_cstring(iqueue, &path, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = सूची_खोलो(path);
	अगर (dirp == शून्य) {
		status = errno_to_portable(त्रुटि_सं);
	} अन्यथा {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		अगर (handle < 0) {
			बंद_सूची(dirp);
		} अन्यथा {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	अगर (status != SSH2_FX_OK)
		send_status(id, status);
	मुक्त(path);
}

अटल व्योम
process_readdir(uint32_t id)
{
	सूची *dirp;
	काष्ठा dirent *dp;
	अक्षर *path;
	पूर्णांक r, handle;

	अगर ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	अगर (dirp == शून्य || path == शून्य) {
		send_status(id, SSH2_FX_FAILURE);
	} अन्यथा {
		काष्ठा stat st;
		अक्षर *pathname;
		Stat *stats;
		पूर्णांक nstats = 10, गिनती = 0, i;

		stats = xcalloc(nstats, माप(Stat));
		जबतक ((dp = सूची_पढ़ो(dirp)) != शून्य) {
			अगर (गिनती >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, माप(Stat));
			}
			xasprintf(&pathname, "%s%s%s", path,
			    म_भेद(path, "/") ? "/" : "", dp->d_name);
			r = lstat(pathname, &st);
			मुक्त(pathname);
			अगर (r == -1)
				जारी;
			stat_to_attrib(&st, &(stats[गिनती].attrib));
			stats[गिनती].name = xstrdup(dp->d_name);
			stats[गिनती].long_name = ls_file(dp->d_name, &st,
			    0, 0, शून्य, शून्य);
			गिनती++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			अगर (गिनती == 100)
				अवरोध;
		}
		अगर (गिनती > 0) {
			send_names(id, गिनती, stats);
			क्रम (i = 0; i < गिनती; i++) {
				मुक्त(stats[i].name);
				मुक्त(stats[i].long_name);
			}
		} अन्यथा {
			send_status(id, SSH2_FX_EOF);
		}
		मुक्त(stats);
	}
}

अटल व्योम
process_remove(uint32_t id)
{
	अक्षर *name;
	पूर्णांक r, status = SSH2_FX_FAILURE;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_mkdir(uint32_t id)
{
	Attrib a;
	अक्षर *name;
	पूर्णांक r, mode, status = SSH2_FX_FAILURE;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	r = सूची_गढ़ो(name, mode);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_rmdir(uint32_t id)
{
	अक्षर *name;
	पूर्णांक r, status;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = सूची_हटाओ(name);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_realpath(uint32_t id)
{
	अक्षर resolvedname[PATH_MAX];
	अक्षर *path;
	पूर्णांक r;

	अगर ((r = sshbuf_get_cstring(iqueue, &path, शून्य)) != 0)
		fatal_fr(r, "parse");

	अगर (path[0] == '\0') {
		मुक्त(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	अगर (sftp_realpath(path, resolvedname) == शून्य) {
		send_status(id, errno_to_portable(त्रुटि_सं));
	} अन्यथा {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	मुक्त(path);
}

अटल व्योम
process_rename(uint32_t id)
{
	अक्षर *oldpath, *newpath;
	पूर्णांक r, status;
	काष्ठा stat sb;

	अगर ((r = sshbuf_get_cstring(iqueue, &oldpath, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	अगर (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(त्रुटि_सं);
	अन्यथा अगर (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		अगर (link(oldpath, newpath) == -1) {
			अगर (त्रुटि_सं == EOPNOTSUPP || त्रुटि_सं == ENOSYS
#अगर_घोषित EXDEV
			    || त्रुटि_सं == EXDEV
#पूर्ण_अगर
#अगर_घोषित LINK_OPNOTSUPP_ERRNO
			    || त्रुटि_सं == LINK_OPNOTSUPP_ERRNO
#पूर्ण_अगर
			    ) {
				काष्ठा stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				अगर (stat(newpath, &st) == -1) {
					अगर (नाम(oldpath, newpath) == -1)
						status =
						    errno_to_portable(त्रुटि_सं);
					अन्यथा
						status = SSH2_FX_OK;
				}
			} अन्यथा {
				status = errno_to_portable(त्रुटि_सं);
			}
		} अन्यथा अगर (unlink(oldpath) == -1) {
			status = errno_to_portable(त्रुटि_सं);
			/* clean spare link */
			unlink(newpath);
		} अन्यथा
			status = SSH2_FX_OK;
	} अन्यथा अगर (stat(newpath, &sb) == -1) {
		अगर (नाम(oldpath, newpath) == -1)
			status = errno_to_portable(त्रुटि_सं);
		अन्यथा
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	मुक्त(oldpath);
	मुक्त(newpath);
}

अटल व्योम
process_readlink(uint32_t id)
{
	पूर्णांक r, len;
	अक्षर buf[PATH_MAX];
	अक्षर *path;

	अगर ((r = sshbuf_get_cstring(iqueue, &path, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	अगर ((len = readlink(path, buf, माप(buf) - 1)) == -1)
		send_status(id, errno_to_portable(त्रुटि_सं));
	अन्यथा {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	मुक्त(path);
}

अटल व्योम
process_symlink(uint32_t id)
{
	अक्षर *oldpath, *newpath;
	पूर्णांक r, status;

	अगर ((r = sshbuf_get_cstring(iqueue, &oldpath, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(oldpath);
	मुक्त(newpath);
}

अटल व्योम
process_extended_posix_rename(uint32_t id)
{
	अक्षर *oldpath, *newpath;
	पूर्णांक r, status;

	अगर ((r = sshbuf_get_cstring(iqueue, &oldpath, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = नाम(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(oldpath);
	मुक्त(newpath);
}

अटल व्योम
process_extended_statvfs(uint32_t id)
{
	अक्षर *path;
	काष्ठा statvfs st;
	पूर्णांक r;

	अगर ((r = sshbuf_get_cstring(iqueue, &path, शून्य)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: statvfs", id);
	logit("statvfs \"%s\"", path);

	अगर (statvfs(path, &st) != 0)
		send_status(id, errno_to_portable(त्रुटि_सं));
	अन्यथा
		send_statvfs(id, &st);
	मुक्त(path);
}

अटल व्योम
process_extended_fstatvfs(uint32_t id)
{
	पूर्णांक r, handle, fd;
	काष्ठा statvfs st;

	अगर ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug("request %u: fstatvfs \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	अगर ((fd = handle_to_fd(handle)) < 0) {
		send_status(id, SSH2_FX_FAILURE);
		वापस;
	}
	अगर (fstatvfs(fd, &st) != 0)
		send_status(id, errno_to_portable(त्रुटि_सं));
	अन्यथा
		send_statvfs(id, &st);
}

अटल व्योम
process_extended_hardlink(uint32_t id)
{
	अक्षर *oldpath, *newpath;
	पूर्णांक r, status;

	अगर ((r = sshbuf_get_cstring(iqueue, &oldpath, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	send_status(id, status);
	मुक्त(oldpath);
	मुक्त(newpath);
}

अटल व्योम
process_extended_fsync(uint32_t id)
{
	पूर्णांक handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	अगर ((r = get_handle(iqueue, &handle)) != 0)
		fatal_fr(r, "parse");
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	अगर ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	अन्यथा अगर (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(त्रुटि_सं) : SSH2_FX_OK;
	}
	send_status(id, status);
}

अटल व्योम
process_extended_lsetstat(uint32_t id)
{
	Attrib a;
	अक्षर *name;
	पूर्णांक r, status = SSH2_FX_OK;

	अगर ((r = sshbuf_get_cstring(iqueue, &name, शून्य)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal_fr(r, "parse");

	debug("request %u: lsetstat name \"%s\"", id, name);
	अगर (a.flags & SSH2_FILEXFER_ATTR_आकार) {
		/* nonsensical for links */
		status = SSH2_FX_BAD_MESSAGE;
		जाओ out;
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = fchmodat(AT_FDCWD, name,
		    a.perm & 07777, AT_SYMLINK_NOFOLLOW);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		अक्षर buf[64];
		समय_प्रकार t = a.mtime;

		स_माला(buf, माप(buf), "%Y%m%d-%H:%M:%S",
		    स_स्थानीय(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimensat(AT_FDCWD, name,
		    attrib_to_ts(&a), AT_SYMLINK_NOFOLLOW);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
	अगर (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = fchownat(AT_FDCWD, name, a.uid, a.gid,
		    AT_SYMLINK_NOFOLLOW);
		अगर (r == -1)
			status = errno_to_portable(त्रुटि_सं);
	}
 out:
	send_status(id, status);
	मुक्त(name);
}

अटल व्योम
process_extended_limits(uint32_t id)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;
	uint64_t nfiles = 0;
#अगर defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	काष्ठा rlimit rlim;
#पूर्ण_अगर

	debug("request %u: limits", id);

#अगर defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	अगर (getrlimit(RLIMIT_NOFILE, &rlim) != -1 && rlim.rlim_cur > 5)
		nfiles = rlim.rlim_cur - 5; /* stdio(3) + syslog + spare */
#पूर्ण_अगर

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    /* max-packet-length */
	    (r = sshbuf_put_u64(संदेश, SFTP_MAX_संदेश_लंबाई)) != 0 ||
	    /* max-read-length */
	    (r = sshbuf_put_u64(संदेश, SFTP_MAX_READ_लंबाई)) != 0 ||
	    /* max-write-length */
	    (r = sshbuf_put_u64(संदेश, SFTP_MAX_संदेश_लंबाई - 1024)) != 0 ||
	    /* max-open-handles */
	    (r = sshbuf_put_u64(संदेश, nfiles)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(संदेश);
	sshbuf_free(संदेश);
}

अटल व्योम
process_extended_expand(uint32_t id)
{
	अक्षर cwd[PATH_MAX], resolvedname[PATH_MAX];
	अक्षर *path, *npath;
	पूर्णांक r;
	Stat s;

	अगर ((r = sshbuf_get_cstring(iqueue, &path, शून्य)) != 0)
		fatal_fr(r, "parse");
	अगर (getcwd(cwd, माप(cwd)) == शून्य) {
		send_status(id, errno_to_portable(त्रुटि_सं));
		जाओ out;
	}

	debug3("request %u: expand, original \"%s\"", id, path);
	अगर (path[0] == '\0') {
		/* empty path */
		मुक्त(path);
		path = xstrdup(".");
	} अन्यथा अगर (*path == '~') {
		/* ~ expand path */
		/* Special-case for "~" and "~/" to respect homedir flag */
		अगर (म_भेद(path, "~") == 0) {
			मुक्त(path);
			path = xstrdup(cwd);
		} अन्यथा अगर (म_भेदन(path, "~/", 2) == 0) {
			npath = xstrdup(path + 2);
			मुक्त(path);
			xasprintf(&path, "%s/%s", cwd, npath);
			मुक्त(npath);
		} अन्यथा {
			/* ~user expansions */
			अगर (tilde_expand(path, pw->pw_uid, &npath) != 0) {
				send_status_errmsg(id,
				    errno_to_portable(ENOENT), "no such user");
				जाओ out;
			}
			मुक्त(path);
			path = npath;
		}
	} अन्यथा अगर (*path != '/') {
		/* relative path */
		xasprintf(&npath, "%s/%s", cwd, path);
		मुक्त(path);
		path = npath;
	}
	verbose("expand \"%s\"", path);
	अगर (sftp_realpath(path, resolvedname) == शून्य) {
		send_status(id, errno_to_portable(त्रुटि_सं));
		जाओ out;
	}
	attrib_clear(&s.attrib);
	s.name = s.long_name = resolvedname;
	send_names(id, 1, &s);
 out:
	मुक्त(path);
}

अटल व्योम
process_extended_copy_तथ्य(uint32_t id)
{
	u_char buf[64*1024];
	पूर्णांक read_handle, read_fd, write_handle, write_fd;
	uint64_t len, read_off, read_len, write_off;
	पूर्णांक r, copy_until_eof, status = SSH2_FX_OP_UNSUPPORTED;
	माप_प्रकार ret;
	काष्ठा stat st_read, st_write;

	अगर ((r = get_handle(iqueue, &read_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_off)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &read_len)) != 0 ||
	    (r = get_handle(iqueue, &write_handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &write_off)) != 0)
		fatal_fr(r, "buffer error");

	debug("request %u: copy-data from \"%s\" (handle %d) off %llu len %llu "
	    "to \"%s\" (handle %d) off %llu",
	    id, handle_to_name(read_handle), read_handle,
	    (अचिन्हित दीर्घ दीर्घ)read_off, (अचिन्हित दीर्घ दीर्घ)read_len,
	    handle_to_name(write_handle), write_handle,
	    (अचिन्हित दीर्घ दीर्घ)write_off);

	/* For read length of 0, we read until EOF. */
	अगर (read_len == 0) {
		read_len = (uint64_t)-1 - read_off;
		copy_until_eof = 1;
	} अन्यथा
		copy_until_eof = 0;

	/* Disallow reading & writing to the same handle, path or inode */
	read_fd = handle_to_fd(read_handle);
	write_fd = handle_to_fd(write_handle);
	अगर (read_fd < 0 || write_fd < 0) {
		error_f("bad read or write fd");
		status = errno_to_portable(EBADF);
		जाओ out;
	}
	अगर (ख_स्थिति(read_fd, &st_read) != 0) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("fstat read_fd failed: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (ख_स्थिति(write_fd, &st_write) != 0) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("fstat write_fd failed: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर (read_handle == write_handle ||
	    !म_भेद(handle_to_name(read_handle), handle_to_name(write_handle)) ||
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
		जाओ out;
	}

	अगर (lseek(read_fd, read_off, शुरू_से) < 0) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("read_seek failed");
		जाओ out;
	}

	अगर ((handle_to_flags(write_handle) & O_APPEND) == 0 &&
	    lseek(write_fd, write_off, शुरू_से) < 0) {
		status = errno_to_portable(त्रुटि_सं);
		error_f("write_seek failed");
		जाओ out;
	}

	/* Process the request in chunks. */
	जबतक (read_len > 0 || copy_until_eof) {
		len = MINIMUM(माप(buf), read_len);
		read_len -= len;

		ret = atomicio(पढ़ो, read_fd, buf, len);
		अगर (ret == 0 && त्रुटि_सं == EPIPE) {
			status = copy_until_eof ? SSH2_FX_OK : SSH2_FX_EOF;
			अवरोध;
		} अन्यथा अगर (ret == 0) {
			status = errno_to_portable(त्रुटि_सं);
			error_f("read failed: %s", म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		len = ret;
		handle_update_read(read_handle, len);

		ret = atomicio(vwrite, write_fd, buf, len);
		अगर (ret != len) {
			status = errno_to_portable(त्रुटि_सं);
			error("%s: write failed: %llu != %llu: %s", __func__,
			    (अचिन्हित दीर्घ दीर्घ)ret, (अचिन्हित दीर्घ दीर्घ)len,
			    म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		handle_update_write(write_handle, len);
	}

	अगर (read_len == 0)
		status = SSH2_FX_OK;

 out:
	send_status(id, status);
}

अटल व्योम
process_extended_home_directory(uint32_t id)
{
	अक्षर *username;
	काष्ठा passwd *user_pw;
	पूर्णांक r;
	Stat s;

	अगर ((r = sshbuf_get_cstring(iqueue, &username, शून्य)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: home-directory \"%s\"", id, username);
	अगर (username[0] == '\0') {
		user_pw = pw;
	} अन्यथा अगर ((user_pw = getpwnam(username)) == शून्य) {
		send_status(id, SSH2_FX_FAILURE);
		जाओ out;
	}

	verbose("home-directory \"%s\"", user_pw->pw_dir);
	attrib_clear(&s.attrib);
	s.name = s.long_name = user_pw->pw_dir;
	send_names(id, 1, &s);
 out:
	मुक्त(username);
}

अटल व्योम
process_extended_get_users_groups_by_id(uint32_t id)
{
	काष्ठा passwd *user_pw;
	काष्ठा group *gr;
	काष्ठा sshbuf *uids, *gids, *usernames, *groupnames, *संदेश;
	पूर्णांक r;
	u_int n, nusers = 0, ngroups = 0;
	स्थिर अक्षर *name;

	अगर ((usernames = sshbuf_new()) == शून्य ||
	    (groupnames = sshbuf_new()) == शून्य ||
	    (संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_froms(iqueue, &uids)) != 0 ||
	    (r = sshbuf_froms(iqueue, &gids)) != 0)
		fatal_fr(r, "parse");
	debug_f("uids len = %zu, gids len = %zu",
	    sshbuf_len(uids), sshbuf_len(gids));
	जबतक (sshbuf_len(uids) != 0) {
		अगर ((r = sshbuf_get_u32(uids, &n)) != 0)
			fatal_fr(r, "parse inner uid");
		user_pw = getpwuid((uid_t)n);
		name = user_pw == शून्य ? "" : user_pw->pw_name;
		debug3_f("uid %u => \"%s\"", n, name);
		अगर ((r = sshbuf_put_cstring(usernames, name)) != 0)
			fatal_fr(r, "assemble uid reply");
		nusers++;
	}
	जबतक (sshbuf_len(gids) != 0) {
		अगर ((r = sshbuf_get_u32(gids, &n)) != 0)
			fatal_fr(r, "parse inner gid");
		gr = getgrgid((gid_t)n);
		name = gr == शून्य ? "" : gr->gr_name;
		debug3_f("gid %u => \"%s\"", n, name);
		अगर ((r = sshbuf_put_cstring(groupnames, name)) != 0)
			fatal_fr(r, "assemble gid reply");
		ngroups++;
	}
	verbose("users-groups-by-id: %u users, %u groups", nusers, ngroups);

	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, usernames)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, groupnames)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(संदेश);

	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(usernames);
	sshbuf_free(groupnames);
	sshbuf_free(संदेश);
}

अटल व्योम
process_extended(uint32_t id)
{
	अक्षर *request;
	पूर्णांक r;
	स्थिर काष्ठा sftp_handler *exthand;

	अगर ((r = sshbuf_get_cstring(iqueue, &request, शून्य)) != 0)
		fatal_fr(r, "parse");
	अगर ((exthand = extended_handler_byname(request)) == शून्य) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	} अन्यथा {
		अगर (!request_permitted(exthand))
			send_status(id, SSH2_FX_PERMISSION_DENIED);
		अन्यथा
			exthand->handler(id);
	}
	मुक्त(request);
}

/* stolen from ssh-agent */

अटल व्योम
process(व्योम)
{
	u_int संदेश_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	स्थिर u_char *cp;
	पूर्णांक i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	अगर (buf_len < 5)
		वापस;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	संदेश_len = get_u32(cp);
	अगर (संदेश_len > SFTP_MAX_संदेश_लंबाई) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
		sftp_server_cleanup_exit(11);
	}
	अगर (buf_len < संदेश_len + 4)
		वापस;
	अगर ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal_fr(r, "consume");
	buf_len -= 4;
	अगर ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse type");

	चयन (type) {
	हाल SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		अवरोध;
	हाल SSH2_FXP_EXTENDED:
		अगर (!init_done)
			fatal("Received extended request before init");
		अगर ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse extended ID");
		process_extended(id);
		अवरोध;
	शेष:
		अगर (!init_done)
			fatal("Received %u request before init", type);
		अगर ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal_fr(r, "parse ID");
		क्रम (i = 0; handlers[i].handler != शून्य; i++) {
			अगर (type == handlers[i].type) {
				अगर (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} अन्यथा {
					handlers[i].handler(id);
				}
				अवरोध;
			}
		}
		अगर (handlers[i].handler == शून्य)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	अगर (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		sftp_server_cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	अगर (संदेश_len < consumed) {
		error("msg_len %u < consumed %u", संदेश_len, consumed);
		sftp_server_cleanup_exit(255);
	}
	अगर (संदेश_len > consumed &&
	    (r = sshbuf_consume(iqueue, संदेश_len - consumed)) != 0)
		fatal_fr(r, "consume");
}

/* Cleanup handler that logs active handles upon normal exit */
व्योम
sftp_server_cleanup_exit(पूर्णांक i)
{
	अगर (pw != शून्य && client_addr != शून्य) {
		handle_log_exit();
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_निकास(i);
}

अटल व्योम
sftp_server_usage(व्योम)
{
	बाह्य अक्षर *__progname;

	ख_लिखो(मानक_त्रुटि,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P denied_requests] "
	    "[-p allowed_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	निकास(1);
}

पूर्णांक
sftp_server_main(पूर्णांक argc, अक्षर **argv, काष्ठा passwd *user_pw)
{
	पूर्णांक i, r, in, out, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	अक्षर *cp, *homedir = शून्य, uidstr[32], buf[4*4096];
	दीर्घ mask;

	बाह्य अक्षर *optarg;
	बाह्य अक्षर *__progname;

	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, log_level, log_facility, log_stderr);

	pw = pwcopy(user_pw);

	जबतक (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		चयन (ch) {
		हाल 'Q':
			अगर (strcasecmp(optarg, "requests") != 0) {
				ख_लिखो(मानक_त्रुटि, "Invalid query type\n");
				निकास(1);
			}
			क्रम (i = 0; handlers[i].handler != शून्य; i++)
				म_लिखो("%s\n", handlers[i].name);
			क्रम (i = 0; extended_handlers[i].handler != शून्य; i++)
				म_लिखो("%s\n", extended_handlers[i].name);
			निकास(0);
			अवरोध;
		हाल 'R':
			readonly = 1;
			अवरोध;
		हाल 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			अवरोध;
		हाल 'e':
			log_stderr = 1;
			अवरोध;
		हाल 'l':
			log_level = log_level_संख्या(optarg);
			अगर (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			अवरोध;
		हाल 'f':
			log_facility = log_facility_संख्या(optarg);
			अगर (log_facility == SYSLOG_FACILITY_NOT_SET)
				error("Invalid log facility \"%s\"", optarg);
			अवरोध;
		हाल 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			snprintf(uidstr, माप(uidstr), "%llu",
			    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, "U", uidstr, (अक्षर *)शून्य);
			मुक्त(cp);
			अवरोध;
		हाल 'p':
			अगर (request_allowlist != शून्य)
				fatal("Permitted requests already set");
			request_allowlist = xstrdup(optarg);
			अवरोध;
		हाल 'P':
			अगर (request_denylist != शून्य)
				fatal("Refused requests already set");
			request_denylist = xstrdup(optarg);
			अवरोध;
		हाल 'u':
			त्रुटि_सं = 0;
			mask = म_से_दीर्घ(optarg, &cp, 8);
			अगर (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && त्रुटि_सं != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(व्योम)umask((mode_t)mask);
			अवरोध;
		हाल 'h':
		शेष:
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

	अगर ((cp = दो_पर्या("SSH_CONNECTION")) != शून्य) {
		client_addr = xstrdup(cp);
		अगर ((cp = म_अक्षर(client_addr, ' ')) == शून्य) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    दो_पर्या("SSH_CONNECTION"));
			sftp_server_cleanup_exit(255);
		}
		*cp = '\0';
	} अन्यथा
		client_addr = xstrdup("UNKNOWN");

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#अगर_घोषित HAVE_CYGWIN
	setmode(in, O_द्विआधारी);
	setmode(out, O_द्विआधारी);
#पूर्ण_अगर

	अगर ((iqueue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((oqueue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	अगर (homedir != शून्य) {
		अगर (स_बदलो(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    म_त्रुटि(त्रुटि_सं));
		}
	}

	क्रम (;;) {
		काष्ठा pollfd pfd[2];

		स_रखो(pfd, 0, माप pfd);
		pfd[0].fd = pfd[1].fd = -1;

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		अगर ((r = sshbuf_check_reserve(iqueue, माप(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_संदेश_लंबाई)) == 0) {
			pfd[0].fd = in;
			pfd[0].events = POLLIN;
		}
		अन्यथा अगर (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");

		olen = sshbuf_len(oqueue);
		अगर (olen > 0) {
			pfd[1].fd = out;
			pfd[1].events = POLLOUT;
		}

		अगर (poll(pfd, 2, -1) == -1) {
			अगर (त्रुटि_सं == EINTR)
				जारी;
			error("poll: %s", म_त्रुटि(त्रुटि_सं));
			sftp_server_cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		अगर (pfd[0].revents & (POLLIN|POLLHUP)) {
			len = पढ़ो(in, buf, माप buf);
			अगर (len == 0) {
				debug("read eof");
				sftp_server_cleanup_exit(0);
			} अन्यथा अगर (len == -1) {
				अगर (त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR) {
					error("read: %s", म_त्रुटि(त्रुटि_सं));
					sftp_server_cleanup_exit(1);
				}
			} अन्यथा अगर ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}
		/* send oqueue to stdout */
		अगर (pfd[1].revents & (POLLOUT|POLLHUP)) {
			len = ग_लिखो(out, sshbuf_ptr(oqueue), olen);
			अगर (len == 0 || (len == -1 && त्रुटि_सं == EPIPE)) {
				debug("write eof");
				sftp_server_cleanup_exit(0);
			} अन्यथा अगर (len == -1) {
				sftp_server_cleanup_exit(1);
				अगर (त्रुटि_सं != EAGAIN && त्रुटि_सं != EINTR) {
					error("write: %s", म_त्रुटि(त्रुटि_सं));
					sftp_server_cleanup_exit(1);
				}
			} अन्यथा अगर ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_संदेश_लंबाई);
		अगर (r == 0)
			process();
		अन्यथा अगर (r != SSH_ERR_NO_बफर_SPACE)
			fatal_fr(r, "reserve");
	}
}
