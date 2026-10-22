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
स्थिर अचर वर्ण presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
स्थिर वर्ण *
hostname_hash(माप_प्रकार len)
{
	वर्ण hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	पूर्णाङ्क r;
	माप_प्रकार l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	यदि (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		फर्काऊ रिक्त;
	}
	यदि (gethostname(hostname, परिमाण(hostname)) == -1) {
		error_f("gethostname: %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ रिक्त;
	}
	यदि ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, म_माप(hostname), hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		फर्काऊ रिक्त;
	}
	स_रखो(p, '\0', परिमाण(p));
	लागि (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (परिमाण(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	फर्काऊ xstrdup(p);
}

स्थिर वर्ण *
agent_hostname_hash(शून्य)
{
	फर्काऊ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
स्थिर पूर्णाङ्क
unix_listener_tmp(वर्ण *path, पूर्णाङ्क backlog)
{
	संरचना sockaddr_un sunaddr;
	पूर्णाङ्क good, sock = -1;
	माप_प्रकार i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = म_माप(path);
	जबसम्म (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	स_रखो(&sunaddr, 0, परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	लागि (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		लागि (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(परिमाण(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		यदि (strlcpy(sunaddr.sun_path, path,
		    परिमाण(sunaddr.sun_path)) >= परिमाण(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			रोक;
		}

		यदि ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", म_त्रुटि(त्रुटि_सं));
			रोक;
		}
		यदि (bind(sock, (संरचना sockaddr *)&sunaddr,
		    परिमाण(sunaddr)) == -1) {
			यदि (त्रुटि_सं == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, म_त्रुटि(त्रुटि_सं));
				बंद(sock);
				sock = -1;
				जारी;
			}
			error_f("bind \"%s\": %.100s", path, म_त्रुटि(त्रुटि_सं));
			रोक;
		}
		यदि (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
			रोक;
		}
		good = 1;
	}
	umask(prev_mask);
	यदि (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} अन्यथा यदि (sock != -1) {
		बंद(sock);
		sock = -1;
	}
	फर्काऊ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
स्थिर पूर्णाङ्क
agent_listener_shared(अचर वर्ण *parent_dir, pid_t pid, अचर वर्ण *tag,
    पूर्णाङ्क *sockp, वर्ण **pathp, वर्ण **dirp)
{
	वर्ण *dir = रिक्त, *path = रिक्त;
	पूर्णाङ्क sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = रिक्त;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	यदि (mkdtemp(dir) == रिक्त) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (दीर्घ)pid);
	prev_mask = umask(0177);
	यदि ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		यदि (सूची_हटाओ(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
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
	फर्काऊ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
स्थिर पूर्णाङ्क
agent_listener_user(अचर वर्ण *dir, pid_t pid, अचर वर्ण *tag,
    पूर्णाङ्क *sockp, वर्ण **pathp)
{
	वर्ण *hostnamehash = रिक्त, *path = रिक्त;
	पूर्णाङ्क sock, ret = -1;

	यदि ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == रिक्त)
		फर्काऊ -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (दीर्घ दीर्घ)pid);
	यदि (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		गच्छ out;
	}
	यदि ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		गच्छ out;
	}
	/* Success */
	*pathp = path;
	path = रिक्त; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	मुक्त(hostnamehash);
	मुक्त(path);
	फर्काऊ ret;
}

स्थिर वर्ण *
expand_pathspec(अचर वर्ण *path, अचर वर्ण *username,
    uid_t uid, अचर वर्ण *homedir)
{
	वर्ण *uidbuf = रिक्त, *dir = रिक्त, *tmp = रिक्त;

	xasprintf(&uidbuf, "%lld", (दीर्घ दीर्घ)uid);

	यदि ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, रिक्त)) == रिक्त) {
		error_f("failed to percent-expand agent socket directory");
		गच्छ out;
	}
	यदि (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		गच्छ out;
	}
	यदि (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		मुक्त(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	मुक्त(uidbuf);
	मुक्त(tmp);
	फर्काऊ dir;
}

पूर्णाङ्क
agent_listener(अचर वर्ण *pathspec, अचर वर्ण *username, uid_t uid,
    अचर वर्ण *homedir, pid_t pid, अचर वर्ण *tag, पूर्णाङ्क *sockp,
    वर्ण **pathp, वर्ण **dirp)
{
	पूर्णाङ्क sock = -1, ret = -1;
	वर्ण *path = रिक्त, *dir = रिक्त;

	*sockp = -1;
	*pathp = *dirp = रिक्त;

	यदि (pathspec == रिक्त || pathspec[0] == '\0') {
		error_f("no agent path specified");
		फर्काऊ -1;
	}
	यदि (म_भेदन(pathspec, "shared:", 7) == 0) {
		यदि (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			गच्छ out;
		}
		यदि ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			गच्छ out;
		}
		यदि (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			गच्छ out;
		}
	} अन्यथा यदि (म_भेदन(pathspec, "user:", 5) == 0) {
		यदि ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			गच्छ out;
		}
		यदि (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			गच्छ out;
		}
	} अन्यथा {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		गच्छ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = रिक्त; /* transferred */
 out:
	मुक्त(path);
	मुक्त(dir);
	फर्काऊ ret;
}

पूर्णाङ्क
agent_listener_cleanup(अचर वर्ण *pathspec, अचर वर्ण *sockpath,
    अचर वर्ण *sockdir)
{
	यदि (sockpath == रिक्त)
		फर्काऊ 0;
	यदि (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, म_त्रुटि(त्रुटि_सं));
		फर्काऊ -1;
	}
	debug3_f("removed socket %s", sockpath);

	यदि (pathspec == रिक्त)
		फर्काऊ 0;
	यदि (म_भेदन(pathspec, "shared:", 7) == 0 && sockdir != रिक्त) {
		यदि (सूची_हटाओ(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, म_त्रुटि(त्रुटि_सं));
			फर्काऊ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
socket_is_stale(अचर वर्ण *path)
{
	पूर्णाङ्क fd, r;
	संरचना sockaddr_un sunaddr;
	socklen_t l = परिमाण(r);

	/* attempt non-blocking connect on socket */
	स_रखो(&sunaddr, '\0', परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	यदि (strlcpy(sunaddr.sun_path, path,
	    परिमाण(sunaddr.sun_path)) >= परिमाण(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		फर्काऊ 0;
	}
	यदि ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	यदि (connect(fd, (संरचना sockaddr *)&sunaddr, परिमाण(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		फर्काऊ 1;
	}
	यदि (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		फर्काऊ 0;
	}
	यदि (r != 0) {
		debug_f("socket error on %s: %s", path, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		फर्काऊ 1;
	}
	बंद(fd);
	debug_f("socket %s seems still active", path);
	फर्काऊ 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

शून्य
agent_cleanup_stale(अचर वर्ण *pathspec, अचर वर्ण *username, uid_t uid,
    अचर वर्ण *homedir, पूर्णाङ्क ignore_hosthash)
{
	सूची *d = रिक्त;
	संरचना dirent *dp;
	संरचना stat sb;
	वर्ण *prefix = रिक्त, *dir = रिक्त, *path;
	संरचना timespec now, sub, *mtimp = रिक्त;

	/* Only clean up user socket directories */
	यदि (pathspec == रिक्त || म_भेदन(pathspec, "user:", 5) != 0)
		फर्काऊ;

	यदि ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == रिक्त)
		फर्काऊ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	यदि (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	यदि (!ignore_hosthash) {
		यदि ((path = agent_hostname_hash()) == रिक्त) {
			error_f("couldn't get hostname hash");
			गच्छ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		मुक्त(path);
	}

	यदि ((d = सूची_खोलो(dir)) == रिक्त) {
		यदि (त्रुटि_सं != ENOENT)
			error_f("opendir \"%s\": %s", dir, म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	जबसम्म ((dp = सूची_पढ़ो(d)) != रिक्त) {
#ifdef HAVE_DIRENT_D_TYPE
		यदि (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			जारी;
#endif
		यदि (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && त्रुटि_सं != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		यदि (!S_ISSOCK(sb.st_mode))
			जारी;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#अन्यथा
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		यदि (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			जारी;
		}
		यदि (!ignore_hosthash &&
		    म_भेदन(dp->d_name, prefix, म_माप(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			जारी;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		यदि (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		मुक्त(path);
	}
 out:
	यदि (d != रिक्त)
		बंद_सूची(d);
	मुक्त(dir);
	मुक्त(prefix);
}

#undef unlinkat
#undef fstatat
