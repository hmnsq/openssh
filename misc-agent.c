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

#परिभाषय SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
स्थिर ध्रुव वर्ण presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
स्थिर वर्ण *
hostname_hash(आकार_t len)
{
	वर्ण hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	पूर्णाङ्क r;
	आकार_t l, i;

	l = ssh_digest_अष्टकानि(SSH_DIGEST_SHA512);
	यदि (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		प्रत्यागम रिक्त;
	}
	यदि (gethostname(hostname, परिमाण(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		प्रत्यागम रिक्त;
	}
	यदि ((r = ssh_digest_स्मृतिः(SSH_DIGEST_SHA512,
	    hostname, वाक्यदैर्घ्यम्(hostname), hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		प्रत्यागम रिक्त;
	}
	स्मृतिं_पूरय(p, '\0', परिमाण(p));
	प्रति (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (परिमाण(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	प्रत्यागम xstrdup(p);
}

स्थिर वर्ण *
agent_hostname_hash(शून्य)
{
	प्रत्यागम hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
स्थिर पूर्णाङ्क
unix_listener_tmp(वर्ण *मार्गः, पूर्णाङ्क backlog)
{
	संरचना sockaddr_un sunaddr;
	पूर्णाङ्क good, sock = -1;
	आकार_t i, xstart;
	बहुलकम्_t पूर्व_आवरणम्;

	/* Find first 'X' template character back from end of string */
	xstart = वाक्यदैर्घ्यम्(मार्गः);
	यावत् (xstart > 0 && मार्गः[xstart - 1] == 'X')
		xstart--;

	स्मृतिं_पूरय(&sunaddr, 0, परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	पूर्व_आवरणम् = umask(0177);
	प्रति (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		प्रति (i = xstart; मार्गः[i] != '\0'; i++) {
			मार्गः[i] = presentation_chars[
			    arc4random_एकरूपम्(परिमाण(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", मार्गः);

		यदि (strlcpy(sunaddr.sun_मार्गः, मार्गः,
		    परिमाण(sunaddr.sun_मार्गः)) >= परिमाण(sunaddr.sun_मार्गः)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    मार्गः);
			भङ्ग;
		}

		यदि ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			भङ्ग;
		}
		यदि (bind(sock, (संरचना sockaddr *)&sunaddr,
		    परिमाण(sunaddr)) == -1) {
			यदि (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    मार्गः, strerror(errno));
				close(sock);
				sock = -1;
				अनुवर्त;
			}
			error_f("bind \"%s\": %.100s", मार्गः, strerror(errno));
			भङ्ग;
		}
		यदि (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", मार्गः, strerror(errno));
			भङ्ग;
		}
		good = 1;
	}
	umask(पूर्व_आवरणम्);
	यदि (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    मार्गः, sock);
	} अन्यथा यदि (sock != -1) {
		close(sock);
		sock = -1;
	}
	प्रत्यागम sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
स्थिर पूर्णाङ्क
agent_listener_shared(ध्रुव वर्ण *parent_dir, pid_t pid, ध्रुव वर्ण *चिह्नकम्,
    पूर्णाङ्क *sockp, वर्ण **pathp, वर्ण **dirp)
{
	वर्ण *dir = रिक्त, *मार्गः = रिक्त;
	पूर्णाङ्क sock, ret = -1;
	बहुलकम्_t पूर्व_आवरणम्;

	*pathp = *dirp = रिक्त;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	यदि (mkdtemp(dir) == रिक्त) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	xasprintf(&मार्गः, "%s/agent.%s.%ld", dir, चिह्नकम्, (दीर्घ)pid);
	पूर्व_आवरणम् = umask(0177);
	यदि ((sock = unix_listener(मार्गः, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(पूर्व_आवरणम्);
		यदि (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	umask(पूर्व_आवरणम्);

	/* Success */
	*dirp = dir;
	dir = रिक्त; /* transferred */
	*pathp = मार्गः;
	मार्गः = रिक्त; /* transferred */
	*sockp = sock;
	ret = 0;
 बहिर्गमनम्:
	मुक्त(dir);
	मुक्त(मार्गः);
	प्रत्यागम ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
स्थिर पूर्णाङ्क
agent_listener_user(ध्रुव वर्ण *dir, pid_t pid, ध्रुव वर्ण *चिह्नकम्,
    पूर्णाङ्क *sockp, वर्ण **pathp)
{
	वर्ण *hostnamehash = रिक्त, *मार्गः = रिक्त;
	पूर्णाङ्क sock, ret = -1;

	यदि ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == रिक्त)
		प्रत्यागम -1;
	xasprintf(&मार्गः, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, चिह्नकम्, (दीर्घ दीर्घ)pid);
	यदि (mkdir_मार्गः(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		गच्छ बहिर्गमनम्;
	}
	यदि ((sock = unix_listener_tmp(मार्गः, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		गच्छ बहिर्गमनम्;
	}
	/* Success */
	*pathp = मार्गः;
	मार्गः = रिक्त; /* transferred */
	*sockp = sock;
	ret = 0;
 बहिर्गमनम्:
	मुक्त(hostnamehash);
	मुक्त(मार्गः);
	प्रत्यागम ret;
}

स्थिर वर्ण *
expand_pathspec(ध्रुव वर्ण *मार्गः, ध्रुव वर्ण *username,
    uid_t uid, ध्रुव वर्ण *homedir)
{
	वर्ण *uidbuf = रिक्त, *dir = रिक्त, *tmp = रिक्त;

	xasprintf(&uidbuf, "%lld", (दीर्घ दीर्घ)uid);

	यदि ((tmp = percent_expand(मार्गः, "u", username, "U", uidbuf,
	    "h", homedir, रिक्त)) == रिक्त) {
		error_f("failed to percent-expand agent socket directory");
		गच्छ बहिर्गमनम्;
	}
	यदि (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		गच्छ बहिर्गमनम्;
	}
	यदि (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		मुक्त(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 बहिर्गमनम्:
	मुक्त(uidbuf);
	मुक्त(tmp);
	प्रत्यागम dir;
}

पूर्णाङ्क
agent_listener(ध्रुव वर्ण *pathspec, ध्रुव वर्ण *username, uid_t uid,
    ध्रुव वर्ण *homedir, pid_t pid, ध्रुव वर्ण *चिह्नकम्, पूर्णाङ्क *sockp,
    वर्ण **pathp, वर्ण **dirp)
{
	पूर्णाङ्क sock = -1, ret = -1;
	वर्ण *मार्गः = रिक्त, *dir = रिक्त;

	*sockp = -1;
	*pathp = *dirp = रिक्त;

	यदि (pathspec == रिक्त || pathspec[0] == '\0') {
		error_f("no agent path specified");
		प्रत्यागम -1;
	}
	यदि (वाक्ये_तुलय(pathspec, "shared:", 7) == 0) {
		यदि (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			गच्छ बहिर्गमनम्;
		}
		यदि ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			गच्छ बहिर्गमनम्;
		}
		यदि (agent_listener_shared(dir, pid, चिह्नकम्,
		    &sock, &मार्गः, dirp) != 0) {
			/* Error already logged */
			गच्छ बहिर्गमनम्;
		}
	} अन्यथा यदि (वाक्ये_तुलय(pathspec, "user:", 5) == 0) {
		यदि ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == रिक्त) {
			/* Error already logged */
			गच्छ बहिर्गमनम्;
		}
		यदि (agent_listener_user(dir, pid, चिह्नकम्, &sock, &मार्गः) != 0) {
			/* Error already logged */
			गच्छ बहिर्गमनम्;
		}
	} अन्यथा {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		गच्छ बहिर्गमनम्;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = मार्गः;
	मार्गः = रिक्त; /* transferred */
 बहिर्गमनम्:
	मुक्त(मार्गः);
	मुक्त(dir);
	प्रत्यागम ret;
}

पूर्णाङ्क
agent_listener_cleanup(ध्रुव वर्ण *pathspec, ध्रुव वर्ण *sockpath,
    ध्रुव वर्ण *sockdir)
{
	यदि (sockpath == रिक्त)
		प्रत्यागम 0;
	यदि (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		प्रत्यागम -1;
	}
	debug3_f("removed socket %s", sockpath);

	यदि (pathspec == रिक्त)
		प्रत्यागम 0;
	यदि (वाक्ये_तुलय(pathspec, "shared:", 7) == 0 && sockdir != रिक्त) {
		यदि (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			प्रत्यागम -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
socket_is_stale(ध्रुव वर्ण *मार्गः)
{
	पूर्णाङ्क fd, r;
	संरचना sockaddr_un sunaddr;
	socklen_t l = परिमाण(r);

	/* attempt non-blocking connect on socket */
	स्मृतिं_पूरय(&sunaddr, '\0', परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	यदि (strlcpy(sunaddr.sun_मार्गः, मार्गः,
	    परिमाण(sunaddr.sun_मार्गः)) >= परिमाण(sunaddr.sun_मार्गः)) {
		debug_f("path for \"%s\" too long for sockaddr_un", मार्गः);
		प्रत्यागम 0;
	}
	यदि ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		प्रत्यागम 0;
	}
	समुच्चयः_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	यदि (connect(fd, (संरचना sockaddr *)&sunaddr, परिमाण(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", मार्गः, strerror(errno));
		close(fd);
		प्रत्यागम 1;
	}
	यदि (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		प्रत्यागम 0;
	}
	यदि (r != 0) {
		debug_f("socket error on %s: %s", मार्गः, strerror(errno));
		close(fd);
		प्रत्यागम 1;
	}
	close(fd);
	debug_f("socket %s seems still active", मार्गः);
	प्रत्यागम 0;
}

#यदि_अपरिभाषितम् HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(मार्गः, buf)
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(मार्गः)
#यदि_अन्तः

शून्य
agent_cleanup_stale(ध्रुव वर्ण *pathspec, ध्रुव वर्ण *username, uid_t uid,
    ध्रुव वर्ण *homedir, पूर्णाङ्क ignore_hosthash)
{
	DIR *d = रिक्त;
	संरचना dirent *dp;
	संरचना stat sb;
	वर्ण *उपसर्गः = रिक्त, *dir = रिक्त, *मार्गः;
	संरचना timespec now, sub, *mtimp = रिक्त;

	/* Only clean up user socket directories */
	यदि (pathspec == रिक्त || वाक्ये_तुलय(pathspec, "user:", 5) != 0)
		प्रत्यागम;

	यदि ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == रिक्त)
		प्रत्यागम; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	यदि (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	यदि (!ignore_hosthash) {
		यदि ((मार्गः = agent_hostname_hash()) == रिक्त) {
			error_f("couldn't get hostname hash");
			गच्छ बहिर्गमनम्;
		}
		xasprintf(&उपसर्गः, "s.%s.", मार्गः);
		मुक्त(मार्गः);
	}

	यदि ((d = opendir(dir)) == रिक्त) {
		यदि (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	यावत् ((dp = readdir(d)) != रिक्त) {
#यदि_परिभाषितम् HAVE_DIRENT_D_TYPE
		यदि (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			अनुवर्त;
#यदि_अन्तः
		यदि (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			अनुवर्त;
		}
		यदि (!S_ISSOCK(sb.st_mode))
			अनुवर्त;
#यदि_परिभाषितम् HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#अन्यथा
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#यदि_अन्तः
		यदि (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			अनुवर्त;
		}
		यदि (!ignore_hosthash &&
		    वाक्ये_तुलय(dp->d_name, उपसर्गः, वाक्यदैर्घ्यम्(उपसर्गः)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			अनुवर्त;
		}
		xasprintf(&मार्गः, "%s/%s", dir, dp->d_name);
		यदि (socket_is_stale(मार्गः)) {
			debug_f("cleanup stale socket %s", मार्गः);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		मुक्त(मार्गः);
	}
 बहिर्गमनम्:
	यदि (d != रिक्त)
		closedir(d);
	मुक्त(dir);
	मुक्त(उपसर्गः);
}

#अपरिभाषय unlinkat
#अपरिभाषय fstatat
