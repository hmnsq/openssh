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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <libgen.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ਸਥਿਰ ਅੱਖਰ *
hostname_hash(ਮਾਪ_t len)
{
	ਅੱਖਰ hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	ਪੂਰਨ r;
	ਮਾਪ_t l, i;

	l = ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA512);
	ਜੇ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (gethostname(hostname, ਆਕਾਰ(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA512,
	    hostname, ਲੜੀ_ਲੰਬਾਈ(hostname), hash, ਆਕਾਰ(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ਵਾਪਸ ਨਿਰਾ;
	}
	memset(p, '\0', ਆਕਾਰ(p));
	ਲਈ (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (ਆਕਾਰ(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ਵਾਪਸ xstrdup(p);
}

ਸਥਿਰ ਅੱਖਰ *
agent_hostname_hash(ਖਾਲੀ)
{
	ਵਾਪਸ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ਸਥਿਰ ਪੂਰਨ
unix_listener_tmp(ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ backlog)
{
	ਬਣਤਰ sockaddr_un sunaddr;
	ਪੂਰਨ good, sock = -1;
	ਮਾਪ_t i, xstart;
	ਬਹੁਲਕ_t prev_ਨਕਾਬ;

	/* Find first 'X' template character back from end of string */
	xstart = ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ);
	ਜਦੋਂ (xstart > 0 && ਰਸਤਾ[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, ਆਕਾਰ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_ਨਕਾਬ = umask(0177);
	ਲਈ (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		ਲਈ (i = xstart; ਰਸਤਾ[i] != '\0'; i++) {
			ਰਸਤਾ[i] = presentation_chars[
			    arc4random_ਇਕਸਾਰ(ਆਕਾਰ(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", ਰਸਤਾ);

		ਜੇ (strlcpy(sunaddr.sun_ਰਸਤਾ, ਰਸਤਾ,
		    ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) >= ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    ਰਸਤਾ);
			ਰੋਕੋ;
		}

		ਜੇ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ਰੋਕੋ;
		}
		ਜੇ (bind(sock, (ਬਣਤਰ sockaddr *)&sunaddr,
		    ਆਕਾਰ(sunaddr)) == -1) {
			ਜੇ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    ਰਸਤਾ, strerror(errno));
				close(sock);
				sock = -1;
				ਜਾਰੀ;
			}
			error_f("bind \"%s\": %.100s", ਰਸਤਾ, strerror(errno));
			ਰੋਕੋ;
		}
		ਜੇ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", ਰਸਤਾ, strerror(errno));
			ਰੋਕੋ;
		}
		good = 1;
	}
	umask(prev_ਨਕਾਬ);
	ਜੇ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    ਰਸਤਾ, sock);
	} ਨਹੀਂਤਾਂ ਜੇ (sock != -1) {
		close(sock);
		sock = -1;
	}
	ਵਾਪਸ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ਸਥਿਰ ਪੂਰਨ
agent_listener_shared(ਅਚਲ ਅੱਖਰ *ਮਾਪਾ_dir, pid_t pid, ਅਚਲ ਅੱਖਰ *ਟੈਗ,
    ਪੂਰਨ *sockp, ਅੱਖਰ **pathp, ਅੱਖਰ **dirp)
{
	ਅੱਖਰ *dir = ਨਿਰਾ, *ਰਸਤਾ = ਨਿਰਾ;
	ਪੂਰਨ sock, ret = -1;
	ਬਹੁਲਕ_t prev_ਨਕਾਬ;

	*pathp = *dirp = ਨਿਰਾ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", ਮਾਪਾ_dir);
	ਜੇ (mkdtemp(dir) == ਨਿਰਾ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	xasprintf(&ਰਸਤਾ, "%s/agent.%s.%ld", dir, ਟੈਗ, (ਲੰਮਾ)pid);
	prev_ਨਕਾਬ = umask(0177);
	ਜੇ ((sock = unix_listener(ਰਸਤਾ, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_ਨਕਾਬ);
		ਜੇ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	umask(prev_ਨਕਾਬ);

	/* Success */
	*dirp = dir;
	dir = ਨਿਰਾ; /* transferred */
	*pathp = ਰਸਤਾ;
	ਰਸਤਾ = ਨਿਰਾ; /* transferred */
	*sockp = sock;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(dir);
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ਸਥਿਰ ਪੂਰਨ
agent_listener_user(ਅਚਲ ਅੱਖਰ *dir, pid_t pid, ਅਚਲ ਅੱਖਰ *ਟੈਗ,
    ਪੂਰਨ *sockp, ਅੱਖਰ **pathp)
{
	ਅੱਖਰ *hostnamehash = ਨਿਰਾ, *ਰਸਤਾ = ਨਿਰਾ;
	ਪੂਰਨ sock, ret = -1;

	ਜੇ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	xasprintf(&ਰਸਤਾ, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, ਟੈਗ, (ਲੰਮਾ ਲੰਮਾ)pid);
	ਜੇ (mkdir_ਰਸਤਾ(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((sock = unix_listener_tmp(ਰਸਤਾ, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Success */
	*pathp = ਰਸਤਾ;
	ਰਸਤਾ = ਨਿਰਾ; /* transferred */
	*sockp = sock;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(hostnamehash);
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅੱਖਰ *
expand_pathspec(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *username,
    uid_t uid, ਅਚਲ ਅੱਖਰ *homedir)
{
	ਅੱਖਰ *uidbuf = ਨਿਰਾ, *dir = ਨਿਰਾ, *tmp = ਨਿਰਾ;

	xasprintf(&uidbuf, "%lld", (ਲੰਮਾ ਲੰਮਾ)uid);

	ਜੇ ((tmp = percent_expand(ਰਸਤਾ, "u", username, "U", uidbuf,
	    "h", homedir, ਨਿਰਾ)) == ਨਿਰਾ) {
		error_f("failed to percent-expand agent socket directory");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		ਮੁਕਤ(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(uidbuf);
	ਮੁਕਤ(tmp);
	ਵਾਪਸ dir;
}

ਪੂਰਨ
agent_listener(ਅਚਲ ਅੱਖਰ *pathspec, ਅਚਲ ਅੱਖਰ *username, uid_t uid,
    ਅਚਲ ਅੱਖਰ *homedir, pid_t pid, ਅਚਲ ਅੱਖਰ *ਟੈਗ, ਪੂਰਨ *sockp,
    ਅੱਖਰ **pathp, ਅੱਖਰ **dirp)
{
	ਪੂਰਨ sock = -1, ret = -1;
	ਅੱਖਰ *ਰਸਤਾ = ਨਿਰਾ, *dir = ਨਿਰਾ;

	*sockp = -1;
	*pathp = *dirp = ਨਿਰਾ;

	ਜੇ (pathspec == ਨਿਰਾ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ਵਾਪਸ -1;
	}
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(pathspec, "shared:", 7) == 0) {
		ਜੇ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ਨਿਰਾ) {
			/* Error already logged */
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (agent_listener_shared(dir, pid, ਟੈਗ,
		    &sock, &ਰਸਤਾ, dirp) != 0) {
			/* Error already logged */
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(pathspec, "user:", 5) == 0) {
		ਜੇ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ਨਿਰਾ) {
			/* Error already logged */
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (agent_listener_user(dir, pid, ਟੈਗ, &sock, &ਰਸਤਾ) != 0) {
			/* Error already logged */
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = ਰਸਤਾ;
	ਰਸਤਾ = ਨਿਰਾ; /* transferred */
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਰਸਤਾ);
	ਮੁਕਤ(dir);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
agent_listener_cleanup(ਅਚਲ ਅੱਖਰ *pathspec, ਅਚਲ ਅੱਖਰ *sockpath,
    ਅਚਲ ਅੱਖਰ *sockdir)
{
	ਜੇ (sockpath == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ਵਾਪਸ -1;
	}
	debug3_f("removed socket %s", sockpath);

	ਜੇ (pathspec == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(pathspec, "shared:", 7) == 0 && sockdir != ਨਿਰਾ) {
		ਜੇ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ਵਾਪਸ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
socket_is_stale(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਪੂਰਨ fd, r;
	ਬਣਤਰ sockaddr_un sunaddr;
	socklen_t l = ਆਕਾਰ(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', ਆਕਾਰ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ਜੇ (strlcpy(sunaddr.sun_ਰਸਤਾ, ਰਸਤਾ,
	    ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) >= ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ)) {
		debug_f("path for \"%s\" too long for sockaddr_un", ਰਸਤਾ);
		ਵਾਪਸ 0;
	}
	ਜੇ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ਵਾਪਸ 0;
	}
	ਸੈੱਟ_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ਜੇ (connect(fd, (ਬਣਤਰ sockaddr *)&sunaddr, ਆਕਾਰ(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", ਰਸਤਾ, strerror(errno));
		close(fd);
		ਵਾਪਸ 1;
	}
	ਜੇ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ਵਾਪਸ 0;
	}
	ਜੇ (r != 0) {
		debug_f("socket error on %s: %s", ਰਸਤਾ, strerror(errno));
		close(fd);
		ਵਾਪਸ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", ਰਸਤਾ);
	ਵਾਪਸ 0;
}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(ਰਸਤਾ, buf)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(ਰਸਤਾ)
#ਜੇ_ਅੰਤ

ਖਾਲੀ
agent_cleanup_stale(ਅਚਲ ਅੱਖਰ *pathspec, ਅਚਲ ਅੱਖਰ *username, uid_t uid,
    ਅਚਲ ਅੱਖਰ *homedir, ਪੂਰਨ ignore_hosthash)
{
	DIR *d = ਨਿਰਾ;
	ਬਣਤਰ dirent *dp;
	ਬਣਤਰ stat sb;
	ਅੱਖਰ *ਅਗੇਤਰ = ਨਿਰਾ, *dir = ਨਿਰਾ, *ਰਸਤਾ;
	ਬਣਤਰ timespec now, sub, *mtimp = ਨਿਰਾ;

	/* Only clean up user socket directories */
	ਜੇ (pathspec == ਨਿਰਾ || ਲੜੀ_ਤੁਲਨਾ(pathspec, "user:", 5) != 0)
		ਵਾਪਸ;

	ਜੇ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ਨਿਰਾ)
		ਵਾਪਸ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ਜੇ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ਜੇ (!ignore_hosthash) {
		ਜੇ ((ਰਸਤਾ = agent_hostname_hash()) == ਨਿਰਾ) {
			error_f("couldn't get hostname hash");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		xasprintf(&ਅਗੇਤਰ, "s.%s.", ਰਸਤਾ);
		ਮੁਕਤ(ਰਸਤਾ);
	}

	ਜੇ ((d = opendir(dir)) == ਨਿਰਾ) {
		ਜੇ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜਦੋਂ ((dp = readdir(d)) != ਨਿਰਾ) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_DIRENT_D_TYPE
		ਜੇ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ਜਾਰੀ;
#ਜੇ_ਅੰਤ
		ਜੇ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ਜਾਰੀ;
		}
		ਜੇ (!S_ISSOCK(sb.st_mode))
			ਜਾਰੀ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ਨਹੀਂਤਾਂ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#ਜੇ_ਅੰਤ
		ਜੇ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ਜਾਰੀ;
		}
		ਜੇ (!ignore_hosthash &&
		    ਲੜੀ_ਤੁਲਨਾ(dp->d_name, ਅਗੇਤਰ, ਲੜੀ_ਲੰਬਾਈ(ਅਗੇਤਰ)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ਜਾਰੀ;
		}
		xasprintf(&ਰਸਤਾ, "%s/%s", dir, dp->d_name);
		ਜੇ (socket_is_stale(ਰਸਤਾ)) {
			debug_f("cleanup stale socket %s", ਰਸਤਾ);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		ਮੁਕਤ(ਰਸਤਾ);
	}
 ਬਾਹਰਲਾ:
	ਜੇ (d != ਨਿਰਾ)
		closedir(d);
	ਮੁਕਤ(dir);
	ਮੁਕਤ(ਅਗੇਤਰ);
}

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ unlinkat
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ fstatat
