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

#ವ್ಯಾಖ್ಯಾನಿಸು SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ಸ್ಥಿರ ಅಕ್ಷರ *
hostname_hash(ಗಾತ್ರ_t len)
{
	ಅಕ್ಷರ hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t l, i;

	l = ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA512);
	ಆದರೆ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (gethostname(hostname, ಗಾತ್ರ(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA512,
	    hostname, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hostname), hash, ಗಾತ್ರ(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	memset(p, '\0', ಗಾತ್ರ(p));
	ಗಾಗಿ (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (ಗಾತ್ರ(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ಹಿಂತಿರುಗಿ xstrdup(p);
}

ಸ್ಥಿರ ಅಕ್ಷರ *
agent_hostname_hash(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
unix_listener_tmp(ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ backlog)
{
	ರಚನೆ sockaddr_un sunaddr;
	ಪೂರ್ಣಾಂಕ good, sock = -1;
	ಗಾತ್ರ_t i, xstart;
	ಬಹುಲಕ_t prev_ಮುಖವಾಡ;

	/* Find first 'X' template character back from end of string */
	xstart = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ);
	ಆಗ (xstart > 0 && ಮಾರ್ಗ[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, ಗಾತ್ರ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_ಮುಖವಾಡ = umask(0177);
	ಗಾಗಿ (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		ಗಾಗಿ (i = xstart; ಮಾರ್ಗ[i] != '\0'; i++) {
			ಮಾರ್ಗ[i] = presentation_chars[
			    arc4random_ಏಕರೂಪ(ಗಾತ್ರ(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", ಮಾರ್ಗ);

		ಆದರೆ (strlcpy(sunaddr.sun_ಮಾರ್ಗ, ಮಾರ್ಗ,
		    ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) >= ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    ಮಾರ್ಗ);
			ನಿಲ್ಲಿಸು;
		}

		ಆದರೆ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (bind(sock, (ರಚನೆ sockaddr *)&sunaddr,
		    ಗಾತ್ರ(sunaddr)) == -1) {
			ಆದರೆ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    ಮಾರ್ಗ, strerror(errno));
				close(sock);
				sock = -1;
				ಮುಂದುವರಿ;
			}
			error_f("bind \"%s\": %.100s", ಮಾರ್ಗ, strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", ಮಾರ್ಗ, strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		good = 1;
	}
	umask(prev_ಮುಖವಾಡ);
	ಆದರೆ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    ಮಾರ್ಗ, sock);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sock != -1) {
		close(sock);
		sock = -1;
	}
	ಹಿಂತಿರುಗಿ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
agent_listener_shared(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪೋಷಕ_dir, pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್,
    ಪೂರ್ಣಾಂಕ *sockp, ಅಕ್ಷರ **pathp, ಅಕ್ಷರ **dirp)
{
	ಅಕ್ಷರ *dir = ಖಾಲಿ, *ಮಾರ್ಗ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ sock, ret = -1;
	ಬಹುಲಕ_t prev_ಮುಖವಾಡ;

	*pathp = *dirp = ಖಾಲಿ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", ಪೋಷಕ_dir);
	ಆದರೆ (mkdtemp(dir) == ಖಾಲಿ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	xasprintf(&ಮಾರ್ಗ, "%s/agent.%s.%ld", dir, ಟ್ಯಾಗ್, (ದೀರ್ಘ)pid);
	prev_ಮುಖವಾಡ = umask(0177);
	ಆದರೆ ((sock = unix_listener(ಮಾರ್ಗ, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_ಮುಖವಾಡ);
		ಆದರೆ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	umask(prev_ಮುಖವಾಡ);

	/* Success */
	*dirp = dir;
	dir = ಖಾಲಿ; /* transferred */
	*pathp = ಮಾರ್ಗ;
	ಮಾರ್ಗ = ಖಾಲಿ; /* transferred */
	*sockp = sock;
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(dir);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
agent_listener_user(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dir, pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್,
    ಪೂರ್ಣಾಂಕ *sockp, ಅಕ್ಷರ **pathp)
{
	ಅಕ್ಷರ *hostnamehash = ಖಾಲಿ, *ಮಾರ್ಗ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ sock, ret = -1;

	ಆದರೆ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	xasprintf(&ಮಾರ್ಗ, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, ಟ್ಯಾಗ್, (ದೀರ್ಘ ದೀರ್ಘ)pid);
	ಆದರೆ (mkdir_ಮಾರ್ಗ(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((sock = unix_listener_tmp(ಮಾರ್ಗ, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Success */
	*pathp = ಮಾರ್ಗ;
	ಮಾರ್ಗ = ಖಾಲಿ; /* transferred */
	*sockp = sock;
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(hostnamehash);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
expand_pathspec(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
    uid_t uid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *homedir)
{
	ಅಕ್ಷರ *uidbuf = ಖಾಲಿ, *dir = ಖಾಲಿ, *tmp = ಖಾಲಿ;

	xasprintf(&uidbuf, "%lld", (ದೀರ್ಘ ದೀರ್ಘ)uid);

	ಆದರೆ ((tmp = percent_expand(ಮಾರ್ಗ, "u", username, "U", uidbuf,
	    "h", homedir, ಖಾಲಿ)) == ಖಾಲಿ) {
		error_f("failed to percent-expand agent socket directory");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		ಬಿಡುಗಡೆ(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(uidbuf);
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ dir;
}

ಪೂರ್ಣಾಂಕ
agent_listener(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathspec, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username, uid_t uid,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *homedir, pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್, ಪೂರ್ಣಾಂಕ *sockp,
    ಅಕ್ಷರ **pathp, ಅಕ್ಷರ **dirp)
{
	ಪೂರ್ಣಾಂಕ sock = -1, ret = -1;
	ಅಕ್ಷರ *ಮಾರ್ಗ = ಖಾಲಿ, *dir = ಖಾಲಿ;

	*sockp = -1;
	*pathp = *dirp = ಖಾಲಿ;

	ಆದರೆ (pathspec == ಖಾಲಿ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(pathspec, "shared:", 7) == 0) {
		ಆದರೆ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ಖಾಲಿ) {
			/* Error already logged */
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (agent_listener_shared(dir, pid, ಟ್ಯಾಗ್,
		    &sock, &ಮಾರ್ಗ, dirp) != 0) {
			/* Error already logged */
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(pathspec, "user:", 5) == 0) {
		ಆದರೆ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ಖಾಲಿ) {
			/* Error already logged */
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (agent_listener_user(dir, pid, ಟ್ಯಾಗ್, &sock, &ಮಾರ್ಗ) != 0) {
			/* Error already logged */
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = ಮಾರ್ಗ;
	ಮಾರ್ಗ = ಖಾಲಿ; /* transferred */
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(dir);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
agent_listener_cleanup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathspec, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sockpath,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sockdir)
{
	ಆದರೆ (sockpath == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	debug3_f("removed socket %s", sockpath);

	ಆದರೆ (pathspec == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(pathspec, "shared:", 7) == 0 && sockdir != ಖಾಲಿ) {
		ಆದರೆ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ಹಿಂತಿರುಗಿ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
socket_is_stale(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಪೂರ್ಣಾಂಕ fd, r;
	ರಚನೆ sockaddr_un sunaddr;
	socklen_t l = ಗಾತ್ರ(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', ಗಾತ್ರ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ಆದರೆ (strlcpy(sunaddr.sun_ಮಾರ್ಗ, ಮಾರ್ಗ,
	    ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) >= ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ)) {
		debug_f("path for \"%s\" too long for sockaddr_un", ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ 0;
	}
	ಗಣ_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ಆದರೆ (connect(fd, (ರಚನೆ sockaddr *)&sunaddr, ಗಾತ್ರ(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", ಮಾರ್ಗ, strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಆದರೆ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (r != 0) {
		debug_f("socket error on %s: %s", ಮಾರ್ಗ, strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(ಮಾರ್ಗ, buf)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(ಮಾರ್ಗ)
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ
agent_cleanup_stale(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathspec, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username, uid_t uid,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *homedir, ಪೂರ್ಣಾಂಕ ignore_hosthash)
{
	DIR *d = ಖಾಲಿ;
	ರಚನೆ dirent *dp;
	ರಚನೆ stat sb;
	ಅಕ್ಷರ *ಪೂರ್ವಪ್ರತ್ಯಯ = ಖಾಲಿ, *dir = ಖಾಲಿ, *ಮಾರ್ಗ;
	ರಚನೆ timespec now, sub, *mtimp = ಖಾಲಿ;

	/* Only clean up user socket directories */
	ಆದರೆ (pathspec == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(pathspec, "user:", 5) != 0)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ಆದರೆ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ಆದರೆ (!ignore_hosthash) {
		ಆದರೆ ((ಮಾರ್ಗ = agent_hostname_hash()) == ಖಾಲಿ) {
			error_f("couldn't get hostname hash");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		xasprintf(&ಪೂರ್ವಪ್ರತ್ಯಯ, "s.%s.", ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	}

	ಆದರೆ ((d = opendir(dir)) == ಖಾಲಿ) {
		ಆದರೆ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಗ ((dp = readdir(d)) != ಖಾಲಿ) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_DIRENT_D_TYPE
		ಆದರೆ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ಮುಂದುವರಿ;
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!S_ISSOCK(sb.st_mode))
			ಮುಂದುವರಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ಇಲ್ಲದಿದ್ದರೆ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!ignore_hosthash &&
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(dp->d_name, ಪೂರ್ವಪ್ರತ್ಯಯ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಪೂರ್ವಪ್ರತ್ಯಯ)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ಮುಂದುವರಿ;
		}
		xasprintf(&ಮಾರ್ಗ, "%s/%s", dir, dp->d_name);
		ಆದರೆ (socket_is_stale(ಮಾರ್ಗ)) {
			debug_f("cleanup stale socket %s", ಮಾರ್ಗ);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	}
 ಹೊರಹೋಗು:
	ಆದರೆ (d != ಖಾಲಿ)
		closedir(d);
	ಬಿಡುಗಡೆ(dir);
	ಬಿಡುಗಡೆ(ಪೂರ್ವಪ್ರತ್ಯಯ);
}

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು unlinkat
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು fstatat
