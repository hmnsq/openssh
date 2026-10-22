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
	整数 r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	如果 (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		返回 NULL;
	}
	如果 (gethostname(hostname, sizeof(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		返回 NULL;
	}
	如果 ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		返回 NULL;
	}
	memset(p, '\0', sizeof(p));
	为 (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (sizeof(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	返回 xstrdup(p);
}

static char *
agent_hostname_hash(void)
{
	返回 hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
static 整数
unix_listener_tmp(char *path, 整数 backlog)
{
	struct sockaddr_un sunaddr;
	整数 good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	当 (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	为 (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		为 (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(sizeof(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		如果 (strlcpy(sunaddr.sun_path, path,
		    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			break;
		}

		如果 ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			break;
		}
		如果 (bind(sock, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == -1) {
			如果 (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				continue;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			break;
		}
		如果 (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			break;
		}
		good = 1;
	}
	umask(prev_mask);
	如果 (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} 否则 如果 (sock != -1) {
		close(sock);
		sock = -1;
	}
	返回 sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
static 整数
agent_listener_shared(const char *parent_dir, pid_t pid, const char *tag,
    整数 *sockp, char **pathp, char **dirp)
{
	char *dir = NULL, *path = NULL;
	整数 sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = NULL;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	如果 (mkdtemp(dir) == NULL) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	如果 ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		如果 (rmdir(dir) != 0)
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
	返回 ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
static 整数
agent_listener_user(const char *dir, pid_t pid, const char *tag,
    整数 *sockp, char **pathp)
{
	char *hostnamehash = NULL, *path = NULL;
	整数 sock, ret = -1;

	如果 ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == NULL)
		返回 -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	如果 (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		goto out;
	}
	如果 ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
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
	返回 ret;
}

static char *
expand_pathspec(const char *path, const char *username,
    uid_t uid, const char *homedir)
{
	char *uidbuf = NULL, *dir = NULL, *tmp = NULL;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	如果 ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, NULL)) == NULL) {
		error_f("failed to percent-expand agent socket directory");
		goto out;
	}
	如果 (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		goto out;
	}
	如果 (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		free(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	free(uidbuf);
	free(tmp);
	返回 dir;
}

整数
agent_listener(const char *pathspec, const char *username, uid_t uid,
    const char *homedir, pid_t pid, const char *tag, 整数 *sockp,
    char **pathp, char **dirp)
{
	整数 sock = -1, ret = -1;
	char *path = NULL, *dir = NULL;

	*sockp = -1;
	*pathp = *dirp = NULL;

	如果 (pathspec == NULL || pathspec[0] == '\0') {
		error_f("no agent path specified");
		返回 -1;
	}
	如果 (strncmp(pathspec, "shared:", 7) == 0) {
		如果 (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			goto out;
		}
		如果 ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		如果 (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			goto out;
		}
	} 否则 如果 (strncmp(pathspec, "user:", 5) == 0) {
		如果 ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		如果 (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			goto out;
		}
	} 否则 {
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
	返回 ret;
}

整数
agent_listener_cleanup(const char *pathspec, const char *sockpath,
    const char *sockdir)
{
	如果 (sockpath == NULL)
		返回 0;
	如果 (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		返回 -1;
	}
	debug3_f("removed socket %s", sockpath);

	如果 (pathspec == NULL)
		返回 0;
	如果 (strncmp(pathspec, "shared:", 7) == 0 && sockdir != NULL) {
		如果 (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			返回 -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	返回 0;
}

static 整数
socket_is_stale(const char *path)
{
	整数 fd, r;
	struct sockaddr_un sunaddr;
	socklen_t l = sizeof(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	如果 (strlcpy(sunaddr.sun_path, path,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		返回 0;
	}
	如果 ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		返回 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	如果 (connect(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		返回 1;
	}
	如果 (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		返回 0;
	}
	如果 (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		返回 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	返回 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

void
agent_cleanup_stale(const char *pathspec, const char *username, uid_t uid,
    const char *homedir, 整数 ignore_hosthash)
{
	DIR *d = NULL;
	struct dirent *dp;
	struct stat sb;
	char *prefix = NULL, *dir = NULL, *path;
	struct timespec now, sub, *mtimp = NULL;

	/* Only clean up user socket directories */
	如果 (pathspec == NULL || strncmp(pathspec, "user:", 5) != 0)
		返回;

	如果 ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == NULL)
		返回; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	如果 (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		goto out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	如果 (!ignore_hosthash) {
		如果 ((path = agent_hostname_hash()) == NULL) {
			error_f("couldn't get hostname hash");
			goto out;
		}
		xasprintf(&prefix, "s.%s.", path);
		free(path);
	}

	如果 ((d = opendir(dir)) == NULL) {
		如果 (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	当 ((dp = readdir(d)) != NULL) {
#ifdef HAVE_DIRENT_D_TYPE
		如果 (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			continue;
#endif
		如果 (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			continue;
		}
		如果 (!S_ISSOCK(sb.st_mode))
			continue;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#否则
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		如果 (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			continue;
		}
		如果 (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			continue;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		如果 (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		free(path);
	}
 out:
	如果 (d != NULL)
		closedir(d);
	free(dir);
	free(prefix);
}

#undef unlinkat
#undef fstatat
