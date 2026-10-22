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
	පූර්ණ_සංඛ්‍යා r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	නම් (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ආපසු NULL;
	}
	නම් (gethostname(hostname, parimaa_na(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ආපසු NULL;
	}
	නම් ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, parimaa_na(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ආපසු NULL;
	}
	memset(p, '\0', parimaa_na(p));
	සඳහා (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (parimaa_na(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ආපසු xstrdup(p);
}

static var_na *
agent_hostname_hash(void)
{
	ආපසු hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
static පූර්ණ_සංඛ්‍යා
unix_listener_tmp(var_na *path, පූර්ණ_සංඛ්‍යා backlog)
{
	sa_nracanaa sockaddr_un sunaddr;
	පූර්ණ_සංඛ්‍යා good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	අතරතුර (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	සඳහා (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		සඳහා (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(parimaa_na(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		නම් (strlcpy(sunaddr.sun_path, path,
		    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			bha_nga;
		}

		නම් ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			bha_nga;
		}
		නම් (bind(sock, (sa_nracanaa sockaddr *)&sunaddr,
		    parimaa_na(sunaddr)) == -1) {
			නම් (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				continue;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			bha_nga;
		}
		නම් (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			bha_nga;
		}
		good = 1;
	}
	umask(prev_mask);
	නම් (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} නැතහොත් නම් (sock != -1) {
		close(sock);
		sock = -1;
	}
	ආපසු sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
static පූර්ණ_සංඛ්‍යා
agent_listener_shared(const var_na *parent_dir, pid_t pid, const var_na *tag,
    පූර්ණ_සංඛ්‍යා *sockp, var_na **pathp, var_na **dirp)
{
	var_na *dir = NULL, *path = NULL;
	පූර්ණ_සංඛ්‍යා sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = NULL;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	නම් (mkdtemp(dir) == NULL) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	නම් ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		නම් (rmdir(dir) != 0)
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
	ආපසු ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
static පූර්ණ_සංඛ්‍යා
agent_listener_user(const var_na *dir, pid_t pid, const var_na *tag,
    පූර්ණ_සංඛ්‍යා *sockp, var_na **pathp)
{
	var_na *hostnamehash = NULL, *path = NULL;
	පූර්ණ_සංඛ්‍යා sock, ret = -1;

	නම් ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == NULL)
		ආපසු -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	නම් (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		goto out;
	}
	නම් ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
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
	ආපසු ret;
}

static var_na *
expand_pathspec(const var_na *path, const var_na *username,
    uid_t uid, const var_na *homedir)
{
	var_na *uidbuf = NULL, *dir = NULL, *tmp = NULL;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	නම් ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, NULL)) == NULL) {
		error_f("failed to percent-expand agent socket directory");
		goto out;
	}
	නම් (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		goto out;
	}
	නම් (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		free(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	free(uidbuf);
	free(tmp);
	ආපසු dir;
}

පූර්ණ_සංඛ්‍යා
agent_listener(const var_na *pathspec, const var_na *username, uid_t uid,
    const var_na *homedir, pid_t pid, const var_na *tag, පූර්ණ_සංඛ්‍යා *sockp,
    var_na **pathp, var_na **dirp)
{
	පූර්ණ_සංඛ්‍යා sock = -1, ret = -1;
	var_na *path = NULL, *dir = NULL;

	*sockp = -1;
	*pathp = *dirp = NULL;

	නම් (pathspec == NULL || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ආපසු -1;
	}
	නම් (strncmp(pathspec, "shared:", 7) == 0) {
		නම් (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			goto out;
		}
		නම් ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		නම් (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			goto out;
		}
	} නැතහොත් නම් (strncmp(pathspec, "user:", 5) == 0) {
		නම් ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == NULL) {
			/* Error already logged */
			goto out;
		}
		නම් (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			goto out;
		}
	} නැතහොත් {
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
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
agent_listener_cleanup(const var_na *pathspec, const var_na *sockpath,
    const var_na *sockdir)
{
	නම් (sockpath == NULL)
		ආපසු 0;
	නම් (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ආපසු -1;
	}
	debug3_f("removed socket %s", sockpath);

	නම් (pathspec == NULL)
		ආපසු 0;
	නම් (strncmp(pathspec, "shared:", 7) == 0 && sockdir != NULL) {
		නම් (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ආපසු -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
socket_is_stale(const var_na *path)
{
	පූර්ණ_සංඛ්‍යා fd, r;
	sa_nracanaa sockaddr_un sunaddr;
	socklen_t l = parimaa_na(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	නම් (strlcpy(sunaddr.sun_path, path,
	    parimaa_na(sunaddr.sun_path)) >= parimaa_na(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ආපසු 0;
	}
	නම් ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ආපසු 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	නම් (connect(fd, (sa_nracanaa sockaddr *)&sunaddr, parimaa_na(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ආපසු 1;
	}
	නම් (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ආපසු 0;
	}
	නම් (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ආපසු 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ආපසු 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

void
agent_cleanup_stale(const var_na *pathspec, const var_na *username, uid_t uid,
    const var_na *homedir, පූර්ණ_සංඛ්‍යා ignore_hosthash)
{
	DIR *d = NULL;
	sa_nracanaa dirent *dp;
	sa_nracanaa stat sb;
	var_na *prefix = NULL, *dir = NULL, *path;
	sa_nracanaa timespec now, sub, *mtimp = NULL;

	/* Only clean up user socket directories */
	නම් (pathspec == NULL || strncmp(pathspec, "user:", 5) != 0)
		ආපසු;

	නම් ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == NULL)
		ආපසු; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	නම් (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		goto out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	නම් (!ignore_hosthash) {
		නම් ((path = agent_hostname_hash()) == NULL) {
			error_f("couldn't get hostname hash");
			goto out;
		}
		xasprintf(&prefix, "s.%s.", path);
		free(path);
	}

	නම් ((d = opendir(dir)) == NULL) {
		නම් (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		goto out;
	}
	අතරතුර ((dp = readdir(d)) != NULL) {
#ifdef HAVE_DIRENT_D_TYPE
		නම් (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			continue;
#endif
		නම් (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			continue;
		}
		නම් (!S_ISSOCK(sb.st_mode))
			continue;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#නැතහොත්
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		නම් (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			continue;
		}
		නම් (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			continue;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		නම් (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		free(path);
	}
 out:
	නම් (d != NULL)
		closedir(d);
	free(dir);
	free(prefix);
}

#undef unlinkat
#undef fstatat
