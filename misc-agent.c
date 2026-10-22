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
	𐤀𐤌 (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		أرجع عدم;
	}
	𐤀𐤌 (gethostname(hostname, حجم(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		أرجع عدم;
	}
	𐤀𐤌 ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		أرجع عدم;
	}
	memset(p, '\0', حجم(p));
	لكل (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (حجم(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	أرجع xstrdup(p);
}

ساكن حرف *
agent_hostname_hash(فراغ)
{
	أرجع hostname_hash(SOCKET_HOSTNAME_HASHLEN);
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
	طالما (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	لكل (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		لكل (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(حجم(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		𐤀𐤌 (strlcpy(sunaddr.sun_path, path,
		    حجم(sunaddr.sun_path)) >= حجم(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			اكسر;
		}

		𐤀𐤌 ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			اكسر;
		}
		𐤀𐤌 (bind(sock, (بنية sockaddr *)&sunaddr,
		    حجم(sunaddr)) == -1) {
			𐤀𐤌 (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				استمر;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			اكسر;
		}
		𐤀𐤌 (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			اكسر;
		}
		good = 1;
	}
	umask(prev_mask);
	𐤀𐤌 (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} وإلا 𐤀𐤌 (sock != -1) {
		close(sock);
		sock = -1;
	}
	أرجع sock;
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
	𐤀𐤌 (mkdtemp(dir) == عدم) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		اذهب out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	𐤀𐤌 ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		𐤀𐤌 (rmdir(dir) != 0)
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
	أرجع ret;
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

	𐤀𐤌 ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == عدم)
		أرجع -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	𐤀𐤌 (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		اذهب out;
	}
	𐤀𐤌 ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
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
	أرجع ret;
}

ساكن حرف *
expand_pathspec(ثابت حرف *path, ثابت حرف *username,
    uid_t uid, ثابت حرف *homedir)
{
	حرف *uidbuf = عدم, *dir = عدم, *tmp = عدم;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	𐤀𐤌 ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, عدم)) == عدم) {
		error_f("failed to percent-expand agent socket directory");
		اذهب out;
	}
	𐤀𐤌 (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		اذهب out;
	}
	𐤀𐤌 (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		حرر(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	حرر(uidbuf);
	حرر(tmp);
	أرجع dir;
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

	𐤀𐤌 (pathspec == عدم || pathspec[0] == '\0') {
		error_f("no agent path specified");
		أرجع -1;
	}
	𐤀𐤌 (strncmp(pathspec, "shared:", 7) == 0) {
		𐤀𐤌 (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			اذهب out;
		}
		𐤀𐤌 ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب out;
		}
		𐤀𐤌 (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			اذهب out;
		}
	} وإلا 𐤀𐤌 (strncmp(pathspec, "user:", 5) == 0) {
		𐤀𐤌 ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == عدم) {
			/* Error already logged */
			اذهب out;
		}
		𐤀𐤌 (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			اذهب out;
		}
	} وإلا {
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
	أرجع ret;
}

صحيح
agent_listener_cleanup(ثابت حرف *pathspec, ثابت حرف *sockpath,
    ثابت حرف *sockdir)
{
	𐤀𐤌 (sockpath == عدم)
		أرجع 0;
	𐤀𐤌 (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		أرجع -1;
	}
	debug3_f("removed socket %s", sockpath);

	𐤀𐤌 (pathspec == عدم)
		أرجع 0;
	𐤀𐤌 (strncmp(pathspec, "shared:", 7) == 0 && sockdir != عدم) {
		𐤀𐤌 (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			أرجع -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	أرجع 0;
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
	𐤀𐤌 (strlcpy(sunaddr.sun_path, path,
	    حجم(sunaddr.sun_path)) >= حجم(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		أرجع 0;
	}
	𐤀𐤌 ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		أرجع 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	𐤀𐤌 (connect(fd, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		أرجع 1;
	}
	𐤀𐤌 (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		أرجع 0;
	}
	𐤀𐤌 (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		أرجع 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	أرجع 0;
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
	𐤀𐤌 (pathspec == عدم || strncmp(pathspec, "user:", 5) != 0)
		أرجع;

	𐤀𐤌 ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == عدم)
		أرجع; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	𐤀𐤌 (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		اذهب out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	𐤀𐤌 (!ignore_hosthash) {
		𐤀𐤌 ((path = agent_hostname_hash()) == عدم) {
			error_f("couldn't get hostname hash");
			اذهب out;
		}
		xasprintf(&prefix, "s.%s.", path);
		حرر(path);
	}

	𐤀𐤌 ((d = opendir(dir)) == عدم) {
		𐤀𐤌 (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		اذهب out;
	}
	طالما ((dp = readdir(d)) != عدم) {
#ifdef HAVE_DIRENT_D_TYPE
		𐤀𐤌 (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			استمر;
#endif
		𐤀𐤌 (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			استمر;
		}
		𐤀𐤌 (!S_ISSOCK(sb.st_mode))
			استمر;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#وإلا
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		𐤀𐤌 (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			استمر;
		}
		𐤀𐤌 (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			استمر;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		𐤀𐤌 (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		حرر(path);
	}
 out:
	𐤀𐤌 (d != عدم)
		closedir(d);
	حرر(dir);
	حرر(prefix);
}

#undef unlinkat
#undef fstatat
