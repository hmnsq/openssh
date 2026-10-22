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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

#include "digest.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "ssh.h"
#include "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
static const var_na presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
static var_na *
hostname_hash(size_t len)
{
	var_na hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	puur_naa_nka r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	ꦪꦼꦤ꧀ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ꦮꦭꦶ NULL;
	}
	ꦪꦼꦤ꧀ (gethostname(hostname, parimaa_na(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ꦮꦭꦶ NULL;
	}
	ꦪꦼꦤ꧀ ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, parimaa_na(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ꦮꦭꦶ NULL;
	}
	memset(p, '\0', parimaa_na(p));
	ꦏꦁꦒꦺꦴ (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (parimaa_na(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ꦮꦭꦶ xstrdup(p);
}

static var_na *
agent_hostname_hash(void)
{
	ꦮꦭꦶ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
static puur_naa_nka
unix_listener_tmp(var_na *path, puur_naa_nka backlog)
{
	sa_nracanaa sockaddr_un sunaddr;
	puur_naa_nka good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	ꦱꦼꦢꦼꦭ (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	ꦏꦁꦒꦺꦴ (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		ꦏꦁꦒꦺꦴ (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(parimaa_na(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		ꦪꦼꦤ꧀ (strlcpy(sunaddr.sun_path, path,
		    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			bha_nga;
		}

		ꦪꦼꦤ꧀ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			bha_nga;
		}
		ꦪꦼꦤ꧀ (bind(sock, (sa_nracanaa sockaddr *)&sunaddr,
		    parimaa_na(sunaddr)) == -1) {
			ꦪꦼꦤ꧀ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				continue;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			bha_nga;
		}
		ꦪꦼꦤ꧀ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			bha_nga;
		}
		good = 1;
	}
	umask(prev_mask);
	ꦪꦼꦤ꧀ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (sock != -1) {
		close(sock);
		sock = -1;
	}
	ꦮꦭꦶ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
static puur_naa_nka
agent_listener_shared(const var_na *parent_dir, pid_t pid, const var_na *tag,
    puur_naa_nka *sockp, var_na **pathp, var_na **dirp)
{
	var_na *dir = NULL, *path = NULL;
	puur_naa_nka sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = NULL;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	ꦪꦼꦤ꧀ (mkdtemp(dir) == NULL) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	ꦪꦼꦤ꧀ ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		ꦪꦼꦤ꧀ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = NULL; /* transferred */
	*pathp = path;
	path = NULL; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	free(dir);
	free(path);
	ꦮꦭꦶ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
static puur_naa_nka
agent_listener_user(const var_na *dir, pid_t pid, const var_na *tag,
    puur_naa_nka *sockp, var_na **pathp)
{
	var_na *hostnamehash = NULL, *path = NULL;
	puur_naa_nka sock, ret = -1;

	ꦪꦼꦤ꧀ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == NULL)
		ꦮꦭꦶ -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	ꦪꦼꦤ꧀ (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		goto out;
	}
	ꦪꦼꦤ꧀ ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		goto out;
	}
	/* Success */
	*pathp = path;
	path = NULL; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	free(hostnamehash);
	free(path);
	ꦮꦭꦶ ret;
}

static var_na *
expand_pathspec(const var_na *path, const var_na *username,
    uid_t uid, const var_na *homedir)
{
	var_na *uidbuf = NULL, *dir = NULL, *tmp = NULL;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	ꦪꦼꦤ꧀ ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, NULL)) == NULL) {
		error_f("failed to percent-expand agent socket directory");
		goto out;
	}
	ꦪꦼꦤ꧀ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		goto out;
	}
	ꦪꦼꦤ꧀ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		free(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	free(uidbuf);
	free(tmp);
	ꦮꦭꦶ dir;
}

puur_naa_nka
agent_listener(const var_na *pathspec, const var_na *username, uid_t uid,
    const var_na *homedir, pid_t pid, const var_na *tag, puur_naa_nka *sockp,
    var_na **pathp, var_na **dirp)
{
	puur_naa_nka sock = -1, ret = -1;
	var_na *path = NULL, *dir = NULL;

	*sockp = -1;
	*pathp = *dirp = NULL;

	ꦪꦼꦤ꧀ (pathspec == NULL || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ꦮꦭꦶ -1;
	}
	ꦪꦼꦤ꧀ (strncmp(pathspec, "shared:", 7) == 0) {
		ꦪꦼꦤ꧀ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			goto out;
		}
		ꦪꦼꦤ꧀ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		ꦪꦼꦤ꧀ (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			goto out;
		}
	} ꦭꦶꦪ ꦪꦼꦤ꧀ (strncmp(pathspec, "user:", 5) == 0) {
		ꦪꦼꦤ꧀ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		ꦪꦼꦤ꧀ (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			goto out;
		}
	} ꦭꦶꦪ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		goto out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = NULL; /* transferred */
 out:
	free(path);
	free(dir);
	ꦮꦭꦶ ret;
}

puur_naa_nka
agent_listener_cleanup(const var_na *pathspec, const var_na *sockpath,
    const var_na *sockdir)
{
	ꦪꦼꦤ꧀ (sockpath == NULL)
		ꦮꦭꦶ 0;
	ꦪꦼꦤ꧀ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ꦮꦭꦶ -1;
	}
	debug3_f("removed socket %s", sockpath);

	ꦪꦼꦤ꧀ (pathspec == NULL)
		ꦮꦭꦶ 0;
	ꦪꦼꦤ꧀ (strncmp(pathspec, "shared:", 7) == 0 && sockdir != NULL) {
		ꦪꦼꦤ꧀ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ꦮꦭꦶ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ꦮꦭꦶ 0;
}

static puur_naa_nka
socket_is_stale(const var_na *path)
{
	puur_naa_nka fd, r;
	sa_nracanaa sockaddr_un sunaddr;
	socklen_t l = parimaa_na(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ꦪꦼꦤ꧀ (strlcpy(sunaddr.sun_path, path,
	    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ꦮꦭꦶ 0;
	}
	ꦪꦼꦤ꧀ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ꦮꦭꦶ 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ꦪꦼꦤ꧀ (connect(fd, (sa_nracanaa sockaddr *)&sunaddr, parimaa_na(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ꦮꦭꦶ 1;
	}
	ꦪꦼꦤ꧀ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ꦮꦭꦶ 0;
	}
	ꦪꦼꦤ꧀ (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ꦮꦭꦶ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ꦮꦭꦶ 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

void
agent_cleanup_stale(const var_na *pathspec, const var_na *username, uid_t uid,
    const var_na *homedir, puur_naa_nka ignore_hosthash)
{
	DIR *d = NULL;
	sa_nracanaa dirent *dp;
	sa_nracanaa stat sb;
	var_na *prefix = NULL, *dir = NULL, *path;
	sa_nracanaa timespec now, sub, *mtimp = NULL;

	/* Only clean up user socket directories */
	ꦪꦼꦤ꧀ (pathspec == NULL || strncmp(pathspec, "user:", 5) != 0)
		ꦮꦭꦶ;

	ꦪꦼꦤ꧀ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == NULL)
		ꦮꦭꦶ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ꦪꦼꦤ꧀ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		goto out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ꦪꦼꦤ꧀ (!ignore_hosthash) {
		ꦪꦼꦤ꧀ ((path = agent_hostname_hash()) == NULL) {
			error_f("couldn't get hostname hash");
			goto out;
		}
		xasprintf(&prefix, "s.%s.", path);
		free(path);
	}

	ꦪꦼꦤ꧀ ((d = opendir(dir)) == NULL) {
		ꦪꦼꦤ꧀ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	ꦱꦼꦢꦼꦭ ((dp = readdir(d)) != NULL) {
#ifdef HAVE_DIRENT_D_TYPE
		ꦪꦼꦤ꧀ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			continue;
#endif
		ꦪꦼꦤ꧀ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			continue;
		}
		ꦪꦼꦤ꧀ (!S_ISSOCK(sb.st_mode))
			continue;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ꦭꦶꦪ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		ꦪꦼꦤ꧀ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			continue;
		}
		ꦪꦼꦤ꧀ (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			continue;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		ꦪꦼꦤ꧀ (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		free(path);
	}
 out:
	ꦪꦼꦤ꧀ (d != NULL)
		closedir(d);
	free(dir);
	free(prefix);
}

#undef unlinkat
#undef fstatat
