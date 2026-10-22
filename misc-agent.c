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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/un.h>

#شامل <dirent.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <libgen.h>

#شامل "digest.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "pathnames.h"
#شامل "ssh.h"
#شامل "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ایستا ثابت نویسه presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ایستا نویسه *
hostname_hash(size_t len)
{
	نویسه hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	صحیح r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	اگر (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		بازگشت پوچ;
	}
	اگر (gethostname(hostname, اندازه(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		بازگشت پوچ;
	}
	اگر ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, اندازه(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		بازگشت پوچ;
	}
	memset(p, '\0', اندازه(p));
	برای (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (اندازه(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	بازگشت xstrdup(p);
}

ایستا نویسه *
agent_hostname_hash(تهی)
{
	بازگشت hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ایستا صحیح
unix_listener_tmp(نویسه *path, صحیح backlog)
{
	ساختار sockaddr_un sunaddr;
	صحیح good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	وقتی (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, اندازه(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	برای (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		برای (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(اندازه(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		اگر (strlcpy(sunaddr.sun_path, path,
		    اندازه(sunaddr.sun_path)) >= اندازه(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			بشکن;
		}

		اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			بشکن;
		}
		اگر (bind(sock, (ساختار sockaddr *)&sunaddr,
		    اندازه(sunaddr)) == -1) {
			اگر (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				ادامه;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			بشکن;
		}
		اگر (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			بشکن;
		}
		good = 1;
	}
	umask(prev_mask);
	اگر (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} وگرنه اگر (sock != -1) {
		close(sock);
		sock = -1;
	}
	بازگشت sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ایستا صحیح
agent_listener_shared(ثابت نویسه *parent_dir, pid_t pid, ثابت نویسه *tag,
    صحیح *sockp, نویسه **pathp, نویسه **dirp)
{
	نویسه *dir = پوچ, *path = پوچ;
	صحیح sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = پوچ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	اگر (mkdtemp(dir) == پوچ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		برو out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	اگر ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		اگر (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		برو out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = پوچ; /* transferred */
	*pathp = path;
	path = پوچ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	آزاد(dir);
	آزاد(path);
	بازگشت ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ایستا صحیح
agent_listener_user(ثابت نویسه *dir, pid_t pid, ثابت نویسه *tag,
    صحیح *sockp, نویسه **pathp)
{
	نویسه *hostnamehash = پوچ, *path = پوچ;
	صحیح sock, ret = -1;

	اگر ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == پوچ)
		بازگشت -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	اگر (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		برو out;
	}
	اگر ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		برو out;
	}
	/* Success */
	*pathp = path;
	path = پوچ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	آزاد(hostnamehash);
	آزاد(path);
	بازگشت ret;
}

ایستا نویسه *
expand_pathspec(ثابت نویسه *path, ثابت نویسه *username,
    uid_t uid, ثابت نویسه *homedir)
{
	نویسه *uidbuf = پوچ, *dir = پوچ, *tmp = پوچ;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	اگر ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, پوچ)) == پوچ) {
		error_f("failed to percent-expand agent socket directory");
		برو out;
	}
	اگر (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		برو out;
	}
	اگر (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		آزاد(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	آزاد(uidbuf);
	آزاد(tmp);
	بازگشت dir;
}

صحیح
agent_listener(ثابت نویسه *pathspec, ثابت نویسه *username, uid_t uid,
    ثابت نویسه *homedir, pid_t pid, ثابت نویسه *tag, صحیح *sockp,
    نویسه **pathp, نویسه **dirp)
{
	صحیح sock = -1, ret = -1;
	نویسه *path = پوچ, *dir = پوچ;

	*sockp = -1;
	*pathp = *dirp = پوچ;

	اگر (pathspec == پوچ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		بازگشت -1;
	}
	اگر (strncmp(pathspec, "shared:", 7) == 0) {
		اگر (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			برو out;
		}
		اگر ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == پوچ) {
			/* Error already logged */
			برو out;
		}
		اگر (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			برو out;
		}
	} وگرنه اگر (strncmp(pathspec, "user:", 5) == 0) {
		اگر ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == پوچ) {
			/* Error already logged */
			برو out;
		}
		اگر (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			برو out;
		}
	} وگرنه {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		برو out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = پوچ; /* transferred */
 out:
	آزاد(path);
	آزاد(dir);
	بازگشت ret;
}

صحیح
agent_listener_cleanup(ثابت نویسه *pathspec, ثابت نویسه *sockpath,
    ثابت نویسه *sockdir)
{
	اگر (sockpath == پوچ)
		بازگشت 0;
	اگر (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		بازگشت -1;
	}
	debug3_f("removed socket %s", sockpath);

	اگر (pathspec == پوچ)
		بازگشت 0;
	اگر (strncmp(pathspec, "shared:", 7) == 0 && sockdir != پوچ) {
		اگر (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			بازگشت -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	بازگشت 0;
}

ایستا صحیح
socket_is_stale(ثابت نویسه *path)
{
	صحیح fd, r;
	ساختار sockaddr_un sunaddr;
	socklen_t l = اندازه(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', اندازه(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	اگر (strlcpy(sunaddr.sun_path, path,
	    اندازه(sunaddr.sun_path)) >= اندازه(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		بازگشت 0;
	}
	اگر ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		بازگشت 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	اگر (connect(fd, (ساختار sockaddr *)&sunaddr, اندازه(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		بازگشت 1;
	}
	اگر (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		بازگشت 0;
	}
	اگر (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		بازگشت 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	بازگشت 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

تهی
agent_cleanup_stale(ثابت نویسه *pathspec, ثابت نویسه *username, uid_t uid,
    ثابت نویسه *homedir, صحیح ignore_hosthash)
{
	DIR *d = پوچ;
	ساختار dirent *dp;
	ساختار stat sb;
	نویسه *prefix = پوچ, *dir = پوچ, *path;
	ساختار timespec now, sub, *mtimp = پوچ;

	/* Only clean up user socket directories */
	اگر (pathspec == پوچ || strncmp(pathspec, "user:", 5) != 0)
		بازگشت;

	اگر ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == پوچ)
		بازگشت; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	اگر (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		برو out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	اگر (!ignore_hosthash) {
		اگر ((path = agent_hostname_hash()) == پوچ) {
			error_f("couldn't get hostname hash");
			برو out;
		}
		xasprintf(&prefix, "s.%s.", path);
		آزاد(path);
	}

	اگر ((d = opendir(dir)) == پوچ) {
		اگر (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		برو out;
	}
	وقتی ((dp = readdir(d)) != پوچ) {
#ifdef HAVE_DIRENT_D_TYPE
		اگر (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ادامه;
#endif
		اگر (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ادامه;
		}
		اگر (!S_ISSOCK(sb.st_mode))
			ادامه;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#وگرنه
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		اگر (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ادامه;
		}
		اگر (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ادامه;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		اگر (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		آزاد(path);
	}
 out:
	اگر (d != پوچ)
		closedir(d);
	آزاد(dir);
	آزاد(prefix);
}

#undef unlinkat
#undef fstatat
