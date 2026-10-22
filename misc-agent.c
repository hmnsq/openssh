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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <dirent.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <libgen.h>

#अन्तर्भाव "digest.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
स्थिर स्थिरांक अक्षर presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
स्थिर अक्षर *
hostname_hash(माप_प्रकार len)
{
	अक्षर hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	पूर्णांक r;
	माप_प्रकार l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	जर (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		परत रिक्त;
	}
	जर (gethostname(hostname, आकार(hostname)) == -1) {
		error_f("gethostname: %s", म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	जर ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, म_माप(hostname), hash, आकार(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		परत रिक्त;
	}
	स_रखो(p, '\0', आकार(p));
	साठी (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (आकार(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	परत xstrdup(p);
}

स्थिर अक्षर *
agent_hostname_hash(शून्य)
{
	परत hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
स्थिर पूर्णांक
unix_listener_tmp(अक्षर *path, पूर्णांक backlog)
{
	संरचना sockaddr_un sunaddr;
	पूर्णांक good, sock = -1;
	माप_प्रकार i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = म_माप(path);
	पर्यंत (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	स_रखो(&sunaddr, 0, आकार(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	साठी (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		साठी (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(आकार(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		जर (strlcpy(sunaddr.sun_path, path,
		    आकार(sunaddr.sun_path)) >= आकार(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			थांबा;
		}

		जर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		जर (bind(sock, (संरचना sockaddr *)&sunaddr,
		    आकार(sunaddr)) == -1) {
			जर (त्रुटि_सं == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				सुरूठेवा;
			}
			error_f("bind \"%s\": %.100s", path, म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		जर (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		good = 1;
	}
	umask(prev_mask);
	जर (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} अन्यथा जर (sock != -1) {
		बंद(sock);
		sock = -1;
	}
	परत sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
स्थिर पूर्णांक
agent_listener_shared(स्थिरांक अक्षर *parent_dir, pid_t pid, स्थिरांक अक्षर *tag,
    पूर्णांक *sockp, अक्षर **pathp, अक्षर **dirp)
{
	अक्षर *dir = रिक्त, *path = रिक्त;
	पूर्णांक sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = रिक्त;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	जर (mkdtemp(dir) == रिक्त) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (दीर्घ)pid);
	prev_mask = umask(0177);
	जर ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		जर (सूची_हटाओ(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = रिक्त; /* transferred */
	*pathp = path;
	path = रिक्त; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	मुक्त(dir);
	मुक्त(path);
	परत ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
स्थिर पूर्णांक
agent_listener_user(स्थिरांक अक्षर *dir, pid_t pid, स्थिरांक अक्षर *tag,
    पूर्णांक *sockp, अक्षर **pathp)
{
	अक्षर *hostnamehash = रिक्त, *path = रिक्त;
	पूर्णांक sock, ret = -1;

	जर ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == रिक्त)
		परत -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (दीर्घ दीर्घ)pid);
	जर (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		जा out;
	}
	जर ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		जा out;
	}
	/* Success */
	*pathp = path;
	path = रिक्त; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	मुक्त(hostnamehash);
	मुक्त(path);
	परत ret;
}

स्थिर अक्षर *
expand_pathspec(स्थिरांक अक्षर *path, स्थिरांक अक्षर *username,
    uid_t uid, स्थिरांक अक्षर *homedir)
{
	अक्षर *uidbuf = रिक्त, *dir = रिक्त, *tmp = रिक्त;

	xasprintf(&uidbuf, "%lld", (दीर्घ दीर्घ)uid);

	जर ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, रिक्त)) == रिक्त) {
		error_f("failed to percent-expand agent socket directory");
		जा out;
	}
	जर (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		जा out;
	}
	जर (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		मुक्त(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	मुक्त(uidbuf);
	मुक्त(tmp);
	परत dir;
}

पूर्णांक
agent_listener(स्थिरांक अक्षर *pathspec, स्थिरांक अक्षर *username, uid_t uid,
    स्थिरांक अक्षर *homedir, pid_t pid, स्थिरांक अक्षर *tag, पूर्णांक *sockp,
    अक्षर **pathp, अक्षर **dirp)
{
	पूर्णांक sock = -1, ret = -1;
	अक्षर *path = रिक्त, *dir = रिक्त;

	*sockp = -1;
	*pathp = *dirp = रिक्त;

	जर (pathspec == रिक्त || pathspec[0] == '\0') {
		error_f("no agent path specified");
		परत -1;
	}
	जर (म_भेदन(pathspec, "shared:", 7) == 0) {
		जर (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			जा out;
		}
		जर ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			जा out;
		}
		जर (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			जा out;
		}
	} अन्यथा जर (म_भेदन(pathspec, "user:", 5) == 0) {
		जर ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			जा out;
		}
		जर (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			जा out;
		}
	} अन्यथा {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		जा out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = रिक्त; /* transferred */
 out:
	मुक्त(path);
	मुक्त(dir);
	परत ret;
}

पूर्णांक
agent_listener_cleanup(स्थिरांक अक्षर *pathspec, स्थिरांक अक्षर *sockpath,
    स्थिरांक अक्षर *sockdir)
{
	जर (sockpath == रिक्त)
		परत 0;
	जर (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	debug3_f("removed socket %s", sockpath);

	जर (pathspec == रिक्त)
		परत 0;
	जर (म_भेदन(pathspec, "shared:", 7) == 0 && sockdir != रिक्त) {
		जर (सूची_हटाओ(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, म_त्रुटि(त्रुटि_सं));
			परत -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	परत 0;
}

स्थिर पूर्णांक
socket_is_stale(स्थिरांक अक्षर *path)
{
	पूर्णांक fd, r;
	संरचना sockaddr_un sunaddr;
	socklen_t l = आकार(r);

	/* attempt non-blocking connect on socket */
	स_रखो(&sunaddr, '\0', आकार(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	जर (strlcpy(sunaddr.sun_path, path,
	    आकार(sunaddr.sun_path)) >= आकार(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		परत 0;
	}
	जर ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", म_त्रुटि(त्रुटि_सं));
		परत 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	जर (connect(fd, (संरचना sockaddr *)&sunaddr, आकार(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत 1;
	}
	जर (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत 0;
	}
	जर (r != 0) {
		debug_f("socket error on %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत 1;
	}
	बंद(fd);
	debug_f("socket %s seems still active", path);
	परत 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

शून्य
agent_cleanup_stale(स्थिरांक अक्षर *pathspec, स्थिरांक अक्षर *username, uid_t uid,
    स्थिरांक अक्षर *homedir, पूर्णांक ignore_hosthash)
{
	सूची *d = रिक्त;
	संरचना dirent *dp;
	संरचना stat sb;
	अक्षर *prefix = रिक्त, *dir = रिक्त, *path;
	संरचना timespec now, sub, *mtimp = रिक्त;

	/* Only clean up user socket directories */
	जर (pathspec == रिक्त || म_भेदन(pathspec, "user:", 5) != 0)
		परत;

	जर ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == रिक्त)
		परत; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	जर (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	जर (!ignore_hosthash) {
		जर ((path = agent_hostname_hash()) == रिक्त) {
			error_f("couldn't get hostname hash");
			जा out;
		}
		xasprintf(&prefix, "s.%s.", path);
		मुक्त(path);
	}

	जर ((d = सूची_खोलो(dir)) == रिक्त) {
		जर (त्रुटि_सं != ENOENT)
			error_f("opendir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	पर्यंत ((dp = सूची_पढ़ो(d)) != रिक्त) {
#ifdef HAVE_DIRENT_D_TYPE
		जर (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			सुरूठेवा;
#endif
		जर (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && त्रुटि_सं != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, म_त्रुटि(त्रुटि_सं));
			सुरूठेवा;
		}
		जर (!S_ISSOCK(sb.st_mode))
			सुरूठेवा;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#अन्यथा
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		जर (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			सुरूठेवा;
		}
		जर (!ignore_hosthash &&
		    म_भेदन(dp->d_name, prefix, म_माप(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			सुरूठेवा;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		जर (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		मुक्त(path);
	}
 out:
	जर (d != रिक्त)
		बंद_सूची(d);
	मुक्त(dir);
	मुक्त(prefix);
}

#undef unlinkat
#undef fstatat
