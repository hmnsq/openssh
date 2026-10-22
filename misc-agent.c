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
static const char presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
static char *
hostname_hash(size_t len)
{
	char hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	целое r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	если (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		вернуть NULL;
	}
	если (gethostname(hostname, sizeof(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		вернуть NULL;
	}
	если ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		вернуть NULL;
	}
	memset(p, '\0', sizeof(p));
	для (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (sizeof(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	вернуть xstrdup(p);
}

static char *
agent_hostname_hash(void)
{
	вернуть hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
static целое
unix_listener_tmp(char *path, целое backlog)
{
	struct sockaddr_un sunaddr;
	целое good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	пока (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	для (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		для (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(sizeof(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		если (strlcpy(sunaddr.sun_path, path,
		    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			break;
		}

		если ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			break;
		}
		если (bind(sock, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == -1) {
			если (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				continue;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			break;
		}
		если (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			break;
		}
		good = 1;
	}
	umask(prev_mask);
	если (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} иначе если (sock != -1) {
		close(sock);
		sock = -1;
	}
	вернуть sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
static целое
agent_listener_shared(const char *parent_dir, pid_t pid, const char *tag,
    целое *sockp, char **pathp, char **dirp)
{
	char *dir = NULL, *path = NULL;
	целое sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = NULL;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	если (mkdtemp(dir) == NULL) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	если ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		если (rmdir(dir) != 0)
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
	вернуть ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
static целое
agent_listener_user(const char *dir, pid_t pid, const char *tag,
    целое *sockp, char **pathp)
{
	char *hostnamehash = NULL, *path = NULL;
	целое sock, ret = -1;

	если ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == NULL)
		вернуть -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	если (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		goto out;
	}
	если ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
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
	вернуть ret;
}

static char *
expand_pathspec(const char *path, const char *username,
    uid_t uid, const char *homedir)
{
	char *uidbuf = NULL, *dir = NULL, *tmp = NULL;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	если ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, NULL)) == NULL) {
		error_f("failed to percent-expand agent socket directory");
		goto out;
	}
	если (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		goto out;
	}
	если (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		free(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	free(uidbuf);
	free(tmp);
	вернуть dir;
}

целое
agent_listener(const char *pathspec, const char *username, uid_t uid,
    const char *homedir, pid_t pid, const char *tag, целое *sockp,
    char **pathp, char **dirp)
{
	целое sock = -1, ret = -1;
	char *path = NULL, *dir = NULL;

	*sockp = -1;
	*pathp = *dirp = NULL;

	если (pathspec == NULL || pathspec[0] == '\0') {
		error_f("no agent path specified");
		вернуть -1;
	}
	если (strncmp(pathspec, "shared:", 7) == 0) {
		если (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			goto out;
		}
		если ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		если (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			goto out;
		}
	} иначе если (strncmp(pathspec, "user:", 5) == 0) {
		если ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		если (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			goto out;
		}
	} иначе {
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
	вернуть ret;
}

целое
agent_listener_cleanup(const char *pathspec, const char *sockpath,
    const char *sockdir)
{
	если (sockpath == NULL)
		вернуть 0;
	если (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		вернуть -1;
	}
	debug3_f("removed socket %s", sockpath);

	если (pathspec == NULL)
		вернуть 0;
	если (strncmp(pathspec, "shared:", 7) == 0 && sockdir != NULL) {
		если (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			вернуть -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	вернуть 0;
}

static целое
socket_is_stale(const char *path)
{
	целое fd, r;
	struct sockaddr_un sunaddr;
	socklen_t l = sizeof(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	если (strlcpy(sunaddr.sun_path, path,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		вернуть 0;
	}
	если ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		вернуть 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	если (connect(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		вернуть 1;
	}
	если (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		вернуть 0;
	}
	если (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		вернуть 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	вернуть 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

void
agent_cleanup_stale(const char *pathspec, const char *username, uid_t uid,
    const char *homedir, целое ignore_hosthash)
{
	DIR *d = NULL;
	struct dirent *dp;
	struct stat sb;
	char *prefix = NULL, *dir = NULL, *path;
	struct timespec now, sub, *mtimp = NULL;

	/* Only clean up user socket directories */
	если (pathspec == NULL || strncmp(pathspec, "user:", 5) != 0)
		вернуть;

	если ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == NULL)
		вернуть; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	если (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		goto out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	если (!ignore_hosthash) {
		если ((path = agent_hostname_hash()) == NULL) {
			error_f("couldn't get hostname hash");
			goto out;
		}
		xasprintf(&prefix, "s.%s.", path);
		free(path);
	}

	если ((d = opendir(dir)) == NULL) {
		если (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	пока ((dp = readdir(d)) != NULL) {
#ifdef HAVE_DIRENT_D_TYPE
		если (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			continue;
#endif
		если (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			continue;
		}
		если (!S_ISSOCK(sb.st_mode))
			continue;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#иначе
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		если (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			continue;
		}
		если (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			continue;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		если (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		free(path);
	}
 out:
	если (d != NULL)
		closedir(d);
	free(dir);
	free(prefix);
}

#undef unlinkat
#undef fstatat
