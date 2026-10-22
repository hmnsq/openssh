/* $OpenBSD: misc-agent.c,v 1.11 2026/09/22 22:29:27 djm Exp $ */
/*
 * Copyright (c) 2025 Damien Miller <djm@mindrot.org>
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
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>
#समावेश <sys/un.h>

#समावेश <dirent.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <libgen.h>

#समावेश "digest.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "pathnames.h"
#समावेश "ssh.h"
#समावेश "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#घोषणा SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
अटल स्थिर अक्षर presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
अटल अक्षर *
hostname_hash(माप_प्रकार len)
{
	अक्षर hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	पूर्णांक r;
	माप_प्रकार l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	अगर (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		वापस शून्य;
	}
	अगर (gethostname(hostname, माप(hostname)) == -1) {
		error_f("gethostname: %s", म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	अगर ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, म_माप(hostname), hash, माप(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		वापस शून्य;
	}
	स_रखो(p, '\0', माप(p));
	क्रम (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (माप(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	वापस xstrdup(p);
}

अटल अक्षर *
agent_hostname_hash(व्योम)
{
	वापस hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
अटल पूर्णांक
unix_listener_tmp(अक्षर *path, पूर्णांक backlog)
{
	काष्ठा sockaddr_un sunaddr;
	पूर्णांक good, sock = -1;
	माप_प्रकार i, xstart;
	mode_t पूर्व_mask;

	/* Find first 'X' template character back from end of string */
	xstart = म_माप(path);
	जबतक (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	स_रखो(&sunaddr, 0, माप(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	पूर्व_mask = umask(0177);
	क्रम (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		क्रम (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(माप(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		अगर (strlcpy(sunaddr.sun_path, path,
		    माप(sunaddr.sun_path)) >= माप(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			अवरोध;
		}

		अगर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		अगर (bind(sock, (काष्ठा sockaddr *)&sunaddr,
		    माप(sunaddr)) == -1) {
			अगर (त्रुटि_सं == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				जारी;
			}
			error_f("bind \"%s\": %.100s", path, म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		अगर (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		good = 1;
	}
	umask(पूर्व_mask);
	अगर (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} अन्यथा अगर (sock != -1) {
		बंद(sock);
		sock = -1;
	}
	वापस sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
अटल पूर्णांक
agent_listener_shared(स्थिर अक्षर *parent_dir, pid_t pid, स्थिर अक्षर *tag,
    पूर्णांक *sockp, अक्षर **pathp, अक्षर **dirp)
{
	अक्षर *dir = शून्य, *path = शून्य;
	पूर्णांक sock, ret = -1;
	mode_t पूर्व_mask;

	*pathp = *dirp = शून्य;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	अगर (mkdtemp(dir) == शून्य) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (दीर्घ)pid);
	पूर्व_mask = umask(0177);
	अगर ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(पूर्व_mask);
		अगर (सूची_हटाओ(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	umask(पूर्व_mask);

	/* Success */
	*dirp = dir;
	dir = शून्य; /* transferred */
	*pathp = path;
	path = शून्य; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	मुक्त(dir);
	मुक्त(path);
	वापस ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
अटल पूर्णांक
agent_listener_user(स्थिर अक्षर *dir, pid_t pid, स्थिर अक्षर *tag,
    पूर्णांक *sockp, अक्षर **pathp)
{
	अक्षर *hostnamehash = शून्य, *path = शून्य;
	पूर्णांक sock, ret = -1;

	अगर ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == शून्य)
		वापस -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (दीर्घ दीर्घ)pid);
	अगर (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		जाओ out;
	}
	अगर ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		जाओ out;
	}
	/* Success */
	*pathp = path;
	path = शून्य; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	मुक्त(hostnamehash);
	मुक्त(path);
	वापस ret;
}

अटल अक्षर *
expand_pathspec(स्थिर अक्षर *path, स्थिर अक्षर *username,
    uid_t uid, स्थिर अक्षर *homedir)
{
	अक्षर *uidbuf = शून्य, *dir = शून्य, *tmp = शून्य;

	xasprintf(&uidbuf, "%lld", (दीर्घ दीर्घ)uid);

	अगर ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, शून्य)) == शून्य) {
		error_f("failed to percent-expand agent socket directory");
		जाओ out;
	}
	अगर (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		जाओ out;
	}
	अगर (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		मुक्त(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	मुक्त(uidbuf);
	मुक्त(tmp);
	वापस dir;
}

पूर्णांक
agent_listener(स्थिर अक्षर *pathspec, स्थिर अक्षर *username, uid_t uid,
    स्थिर अक्षर *homedir, pid_t pid, स्थिर अक्षर *tag, पूर्णांक *sockp,
    अक्षर **pathp, अक्षर **dirp)
{
	पूर्णांक sock = -1, ret = -1;
	अक्षर *path = शून्य, *dir = शून्य;

	*sockp = -1;
	*pathp = *dirp = शून्य;

	अगर (pathspec == शून्य || pathspec[0] == '\0') {
		error_f("no agent path specified");
		वापस -1;
	}
	अगर (म_भेदन(pathspec, "shared:", 7) == 0) {
		अगर (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			जाओ out;
		}
		अगर ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == शून्य) {
			/* Error already logged */
			जाओ out;
		}
		अगर (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			जाओ out;
		}
	} अन्यथा अगर (म_भेदन(pathspec, "user:", 5) == 0) {
		अगर ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == शून्य) {
			/* Error already logged */
			जाओ out;
		}
		अगर (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			जाओ out;
		}
	} अन्यथा {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		जाओ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = शून्य; /* transferred */
 out:
	मुक्त(path);
	मुक्त(dir);
	वापस ret;
}

पूर्णांक
agent_listener_cleanup(स्थिर अक्षर *pathspec, स्थिर अक्षर *sockpath,
    स्थिर अक्षर *sockdir)
{
	अगर (sockpath == शून्य)
		वापस 0;
	अगर (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	debug3_f("removed socket %s", sockpath);

	अगर (pathspec == शून्य)
		वापस 0;
	अगर (म_भेदन(pathspec, "shared:", 7) == 0 && sockdir != शून्य) {
		अगर (सूची_हटाओ(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, म_त्रुटि(त्रुटि_सं));
			वापस -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	वापस 0;
}

अटल पूर्णांक
socket_is_stale(स्थिर अक्षर *path)
{
	पूर्णांक fd, r;
	काष्ठा sockaddr_un sunaddr;
	socklen_t l = माप(r);

	/* attempt non-blocking connect on socket */
	स_रखो(&sunaddr, '\0', माप(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	अगर (strlcpy(sunaddr.sun_path, path,
	    माप(sunaddr.sun_path)) >= माप(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		वापस 0;
	}
	अगर ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", म_त्रुटि(त्रुटि_सं));
		वापस 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	अगर (connect(fd, (काष्ठा sockaddr *)&sunaddr, माप(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस 1;
	}
	अगर (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस 0;
	}
	अगर (r != 0) {
		debug_f("socket error on %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस 1;
	}
	बंद(fd);
	debug_f("socket %s seems still active", path);
	वापस 0;
}

#अगर_अघोषित HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#पूर्ण_अगर
#अगर_अघोषित HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#पूर्ण_अगर

व्योम
agent_cleanup_stale(स्थिर अक्षर *pathspec, स्थिर अक्षर *username, uid_t uid,
    स्थिर अक्षर *homedir, पूर्णांक ignore_hosthash)
{
	सूची *d = शून्य;
	काष्ठा dirent *dp;
	काष्ठा stat sb;
	अक्षर *prefix = शून्य, *dir = शून्य, *path;
	काष्ठा timespec now, sub, *mtimp = शून्य;

	/* Only clean up user socket directories */
	अगर (pathspec == शून्य || म_भेदन(pathspec, "user:", 5) != 0)
		वापस;

	अगर ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == शून्य)
		वापस; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	अगर (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	अगर (!ignore_hosthash) {
		अगर ((path = agent_hostname_hash()) == शून्य) {
			error_f("couldn't get hostname hash");
			जाओ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		मुक्त(path);
	}

	अगर ((d = सूची_खोलो(dir)) == शून्य) {
		अगर (त्रुटि_सं != ENOENT)
			error_f("opendir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	जबतक ((dp = सूची_पढ़ो(d)) != शून्य) {
#अगर_घोषित HAVE_DIRENT_D_TYPE
		अगर (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			जारी;
#पूर्ण_अगर
		अगर (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && त्रुटि_सं != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		अगर (!S_ISSOCK(sb.st_mode))
			जारी;
#अगर_घोषित HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#अन्यथा
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#पूर्ण_अगर
		अगर (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			जारी;
		}
		अगर (!ignore_hosthash &&
		    म_भेदन(dp->d_name, prefix, म_माप(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			जारी;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		अगर (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		मुक्त(path);
	}
 out:
	अगर (d != शून्य)
		बंद_सूची(d);
	मुक्त(dir);
	मुक्त(prefix);
}

#अघोषित unlinkat
#अघोषित fstatat
