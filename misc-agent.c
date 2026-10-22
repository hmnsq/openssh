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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <libgen.h>

#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ಸ್ಥಿರ ವರ್ಣ *
hostname_hash(size_t len)
{
	ವರ್ಣ hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	ಯದಿ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (gethostname(hostname, ಪರಿಮಾಣ(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, ಪರಿಮಾಣ(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	memset(p, '\0', ಪರಿಮಾಣ(p));
	ಪ್ರತಿ (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (ಪರಿಮಾಣ(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ಪ್ರತ್ಯಾಗಮ xstrdup(p);
}

ಸ್ಥಿರ ವರ್ಣ *
agent_hostname_hash(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
unix_listener_tmp(ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ backlog)
{
	ಸಂರಚನಾ sockaddr_un sunaddr;
	ಪೂರ್ಣಾಙ್ಕ good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	ಯಾವತ್ (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, ಪರಿಮಾಣ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	ಪ್ರತಿ (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		ಪ್ರತಿ (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(ಪರಿಮಾಣ(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		ಯದಿ (strlcpy(sunaddr.sun_path, path,
		    ಪರಿಮಾಣ(sunaddr.sun_path)) >= ಪರಿಮಾಣ(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			ಭಙ್ಗ;
		}

		ಯದಿ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ಭಙ್ಗ;
		}
		ಯದಿ (bind(sock, (ಸಂರಚನಾ sockaddr *)&sunaddr,
		    ಪರಿಮಾಣ(sunaddr)) == -1) {
			ಯದಿ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				ಅನುವರ್ತ;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			ಭಙ್ಗ;
		}
		ಯದಿ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			ಭಙ್ಗ;
		}
		good = 1;
	}
	umask(prev_mask);
	ಯದಿ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} ಅನ್ಯಥಾ ಯದಿ (sock != -1) {
		close(sock);
		sock = -1;
	}
	ಪ್ರತ್ಯಾಗಮ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
agent_listener_shared(ಧ್ರುವ ವರ್ಣ *parent_dir, pid_t pid, ಧ್ರುವ ವರ್ಣ *tag,
    ಪೂರ್ಣಾಙ್ಕ *sockp, ವರ್ಣ **pathp, ವರ್ಣ **dirp)
{
	ವರ್ಣ *dir = ರಿಕ್ತ, *path = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = ರಿಕ್ತ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	ಯದಿ (mkdtemp(dir) == ರಿಕ್ತ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		ಗಚ್ಛ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	ಯದಿ ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		ಯದಿ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		ಗಚ್ಛ out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = ರಿಕ್ತ; /* transferred */
	*pathp = path;
	path = ರಿಕ್ತ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	ಮುಕ್ತ(dir);
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
agent_listener_user(ಧ್ರುವ ವರ್ಣ *dir, pid_t pid, ಧ್ರುವ ವರ್ಣ *tag,
    ಪೂರ್ಣಾಙ್ಕ *sockp, ವರ್ಣ **pathp)
{
	ವರ್ಣ *hostnamehash = ರಿಕ್ತ, *path = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ sock, ret = -1;

	ಯದಿ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	ಯದಿ (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		ಗಚ್ಛ out;
	}
	/* Success */
	*pathp = path;
	path = ರಿಕ್ತ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	ಮುಕ್ತ(hostnamehash);
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ವರ್ಣ *
expand_pathspec(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *username,
    uid_t uid, ಧ್ರುವ ವರ್ಣ *homedir)
{
	ವರ್ಣ *uidbuf = ರಿಕ್ತ, *dir = ರಿಕ್ತ, *tmp = ರಿಕ್ತ;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	ಯದಿ ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, ರಿಕ್ತ)) == ರಿಕ್ತ) {
		error_f("failed to percent-expand agent socket directory");
		ಗಚ್ಛ out;
	}
	ಯದಿ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		ಗಚ್ಛ out;
	}
	ಯದಿ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		ಮುಕ್ತ(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	ಮುಕ್ತ(uidbuf);
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ dir;
}

ಪೂರ್ಣಾಙ್ಕ
agent_listener(ಧ್ರುವ ವರ್ಣ *pathspec, ಧ್ರುವ ವರ್ಣ *username, uid_t uid,
    ಧ್ರುವ ವರ್ಣ *homedir, pid_t pid, ಧ್ರುವ ವರ್ಣ *tag, ಪೂರ್ಣಾಙ್ಕ *sockp,
    ವರ್ಣ **pathp, ವರ್ಣ **dirp)
{
	ಪೂರ್ಣಾಙ್ಕ sock = -1, ret = -1;
	ವರ್ಣ *path = ರಿಕ್ತ, *dir = ರಿಕ್ತ;

	*sockp = -1;
	*pathp = *dirp = ರಿಕ್ತ;

	ಯದಿ (pathspec == ರಿಕ್ತ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (strncmp(pathspec, "shared:", 7) == 0) {
		ಯದಿ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ರಿಕ್ತ) {
			/* Error already logged */
			ಗಚ್ಛ out;
		}
		ಯದಿ (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ ಯದಿ (strncmp(pathspec, "user:", 5) == 0) {
		ಯದಿ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ರಿಕ್ತ) {
			/* Error already logged */
			ಗಚ್ಛ out;
		}
		ಯದಿ (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		ಗಚ್ಛ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = ರಿಕ್ತ; /* transferred */
 out:
	ಮುಕ್ತ(path);
	ಮುಕ್ತ(dir);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
agent_listener_cleanup(ಧ್ರುವ ವರ್ಣ *pathspec, ಧ್ರುವ ವರ್ಣ *sockpath,
    ಧ್ರುವ ವರ್ಣ *sockdir)
{
	ಯದಿ (sockpath == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	debug3_f("removed socket %s", sockpath);

	ಯದಿ (pathspec == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strncmp(pathspec, "shared:", 7) == 0 && sockdir != ರಿಕ್ತ) {
		ಯದಿ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
socket_is_stale(ಧ್ರುವ ವರ್ಣ *path)
{
	ಪೂರ್ಣಾಙ್ಕ fd, r;
	ಸಂರಚನಾ sockaddr_un sunaddr;
	socklen_t l = ಪರಿಮಾಣ(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', ಪರಿಮಾಣ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ಯದಿ (strlcpy(sunaddr.sun_path, path,
	    ಪರಿಮಾಣ(sunaddr.sun_path)) >= ಪರಿಮಾಣ(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ಯದಿ (connect(fd, (ಸಂರಚನಾ sockaddr *)&sunaddr, ಪರಿಮಾಣ(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಯದಿ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

ಶೂನ್ಯ
agent_cleanup_stale(ಧ್ರುವ ವರ್ಣ *pathspec, ಧ್ರುವ ವರ್ಣ *username, uid_t uid,
    ಧ್ರುವ ವರ್ಣ *homedir, ಪೂರ್ಣಾಙ್ಕ ignore_hosthash)
{
	DIR *d = ರಿಕ್ತ;
	ಸಂರಚನಾ dirent *dp;
	ಸಂರಚನಾ stat sb;
	ವರ್ಣ *prefix = ರಿಕ್ತ, *dir = ರಿಕ್ತ, *path;
	ಸಂರಚನಾ timespec now, sub, *mtimp = ರಿಕ್ತ;

	/* Only clean up user socket directories */
	ಯದಿ (pathspec == ರಿಕ್ತ || strncmp(pathspec, "user:", 5) != 0)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ಯದಿ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ಯದಿ (!ignore_hosthash) {
		ಯದಿ ((path = agent_hostname_hash()) == ರಿಕ್ತ) {
			error_f("couldn't get hostname hash");
			ಗಚ್ಛ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		ಮುಕ್ತ(path);
	}

	ಯದಿ ((d = opendir(dir)) == ರಿಕ್ತ) {
		ಯದಿ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯಾವತ್ ((dp = readdir(d)) != ರಿಕ್ತ) {
#ifdef HAVE_DIRENT_D_TYPE
		ಯದಿ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ಅನುವರ್ತ;
#endif
		ಯದಿ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ಅನುವರ್ತ;
		}
		ಯದಿ (!S_ISSOCK(sb.st_mode))
			ಅನುವರ್ತ;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ಅನ್ಯಥಾ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		ಯದಿ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ಅನುವರ್ತ;
		}
		ಯದಿ (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ಅನುವರ್ತ;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		ಯದಿ (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		ಮುಕ್ತ(path);
	}
 out:
	ಯದಿ (d != ರಿಕ್ತ)
		closedir(d);
	ಮುಕ್ತ(dir);
	ಮುಕ್ತ(prefix);
}

#undef unlinkat
#undef fstatat
