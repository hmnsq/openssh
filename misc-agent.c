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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/un.h>

#ضمن <dirent.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <libgen.h>

#ضمن "digest.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "pathnames.h"
#ضمن "ssh.h"
#ضمن "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ساكن ثابت حرف presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ساكن حرف *
hostname_hash(size_t len)
{
	حرف hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	صحيح r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	אם (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		החזר عدم;
	}
	אם (gethostname(hostname, حجم(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		החזר عدم;
	}
	אם ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		החזר عدم;
	}
	memset(p, '\0', حجم(p));
	עבור (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (حجم(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	החזר xstrdup(p);
}

ساكن حرف *
agent_hostname_hash(فراغ)
{
	החזר hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ساكن صحيح
unix_listener_tmp(حرف *path, صحيح backlog)
{
	بنية sockaddr_un sunaddr;
	صحيح good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	כלעוד (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	עבור (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		עבור (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(حجم(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		אם (strlcpy(sunaddr.sun_path, path,
		    حجم(sunaddr.sun_path)) >= حجم(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			اكسر;
		}

		אם ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			اكسر;
		}
		אם (bind(sock, (بنية sockaddr *)&sunaddr,
		    حجم(sunaddr)) == -1) {
			אם (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				استمر;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			اكسر;
		}
		אם (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			اكسر;
		}
		good = 1;
	}
	umask(prev_mask);
	אם (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} אחרת אם (sock != -1) {
		close(sock);
		sock = -1;
	}
	החזר sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ساكن صحيح
agent_listener_shared(ثابت حرف *parent_dir, pid_t pid, ثابت حرف *tag,
    صحيح *sockp, حرف **pathp, حرف **dirp)
{
	حرف *dir = عدم, *path = عدم;
	صحيح sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = عدم;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	אם (mkdtemp(dir) == عدم) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		اذهب out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	אם ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		אם (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		اذهب out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = عدم; /* transferred */
	*pathp = path;
	path = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	حرر(dir);
	حرر(path);
	החזר ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ساكن صحيح
agent_listener_user(ثابت حرف *dir, pid_t pid, ثابت حرف *tag,
    صحيح *sockp, حرف **pathp)
{
	حرف *hostnamehash = عدم, *path = عدم;
	صحيح sock, ret = -1;

	אם ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == عدم)
		החזר -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	אם (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		اذهب out;
	}
	אם ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		اذهب out;
	}
	/* Success */
	*pathp = path;
	path = عدم; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	حرر(hostnamehash);
	حرر(path);
	החזר ret;
}

ساكن حرف *
expand_pathspec(ثابت حرف *path, ثابت حرف *username,
    uid_t uid, ثابت حرف *homedir)
{
	حرف *uidbuf = عدم, *dir = عدم, *tmp = عدم;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	אם ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, عدم)) == عدم) {
		error_f("failed to percent-expand agent socket directory");
		اذهب out;
	}
	אם (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		اذهب out;
	}
	אם (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		حرر(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	حرر(uidbuf);
	حرر(tmp);
	החזר dir;
}

صحيح
agent_listener(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, pid_t pid, ثابت حرف *tag, صحيح *sockp,
    حرف **pathp, حرف **dirp)
{
	صحيح sock = -1, ret = -1;
	حرف *path = عدم, *dir = عدم;

	*sockp = -1;
	*pathp = *dirp = عدم;

	אם (pathspec == عدم || pathspec[0] == '\0') {
		error_f("no agent path specified");
		החזר -1;
	}
	אם (strncmp(pathspec, "shared:", 7) == 0) {
		אם (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			اذهب out;
		}
		אם ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب out;
		}
		אם (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			اذهب out;
		}
	} אחרת אם (strncmp(pathspec, "user:", 5) == 0) {
		אם ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب out;
		}
		אם (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			اذهب out;
		}
	} אחרת {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		اذهب out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = عدم; /* transferred */
 out:
	حرر(path);
	حرر(dir);
	החזר ret;
}

صحيح
agent_listener_cleanup(ثابت حرف *pathspec, ثابت حرف *sockpath,
    ثابت حرف *sockdir)
{
	אם (sockpath == عدم)
		החזר 0;
	אם (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		החזר -1;
	}
	debug3_f("removed socket %s", sockpath);

	אם (pathspec == عدم)
		החזר 0;
	אם (strncmp(pathspec, "shared:", 7) == 0 && sockdir != عدم) {
		אם (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			החזר -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	החזר 0;
}

ساكن صحيح
socket_is_stale(ثابت حرف *path)
{
	صحيح fd, r;
	بنية sockaddr_un sunaddr;
	socklen_t l = حجم(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	אם (strlcpy(sunaddr.sun_path, path,
	    حجم(sunaddr.sun_path)) >= حجم(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		החזר 0;
	}
	אם ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		החזר 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	אם (connect(fd, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		החזר 1;
	}
	אם (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		החזר 0;
	}
	אם (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		החזר 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	החזר 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

فراغ
agent_cleanup_stale(ثابت حرف *pathspec, ثابت حرف *username, uid_t uid,
    ثابت حرف *homedir, صحيح ignore_hosthash)
{
	DIR *d = عدم;
	بنية dirent *dp;
	بنية stat sb;
	حرف *prefix = عدم, *dir = عدم, *path;
	بنية timespec now, sub, *mtimp = عدم;

	/* Only clean up user socket directories */
	אם (pathspec == عدم || strncmp(pathspec, "user:", 5) != 0)
		החזר;

	אם ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == عدم)
		החזר; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	אם (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		اذهب out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	אם (!ignore_hosthash) {
		אם ((path = agent_hostname_hash()) == عدم) {
			error_f("couldn't get hostname hash");
			اذهب out;
		}
		xasprintf(&prefix, "s.%s.", path);
		حرر(path);
	}

	אם ((d = opendir(dir)) == عدم) {
		אם (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		اذهب out;
	}
	כלעוד ((dp = readdir(d)) != عدم) {
#ifdef HAVE_DIRENT_D_TYPE
		אם (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			استمر;
#endif
		אם (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			استمر;
		}
		אם (!S_ISSOCK(sb.st_mode))
			استمر;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#אחרת
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		אם (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			استمر;
		}
		אם (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			استمر;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		אם (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		حرر(path);
	}
 out:
	אם (d != عدم)
		closedir(d);
	حرر(dir);
	حرر(prefix);
}

#undef unlinkat
#undef fstatat
