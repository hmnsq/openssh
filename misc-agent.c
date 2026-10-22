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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <libgen.h>

#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
സ്ഥിതം സ്ഥിരം അക്ഷരം presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
സ്ഥിതം അക്ഷരം *
hostname_hash(size_t len)
{
	അക്ഷരം hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	പൂർണ്ണസംഖ്യ r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	എങ്കിൽ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (gethostname(hostname, വലുപ്പം(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, വലുപ്പം(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		തിരികെ ശൂന്യ;
	}
	memset(p, '\0', വലുപ്പം(p));
	വേണ്ടി (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (വലുപ്പം(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	തിരികെ xstrdup(p);
}

സ്ഥിതം അക്ഷരം *
agent_hostname_hash(ശൂന്യം)
{
	തിരികെ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
unix_listener_tmp(അക്ഷരം *path, പൂർണ്ണസംഖ്യ backlog)
{
	ഘടന sockaddr_un sunaddr;
	പൂർണ്ണസംഖ്യ good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	ആകുമ്പോൾ (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, വലുപ്പം(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	വേണ്ടി (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		വേണ്ടി (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(വലുപ്പം(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		എങ്കിൽ (strlcpy(sunaddr.sun_path, path,
		    വലുപ്പം(sunaddr.sun_path)) >= വലുപ്പം(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			നിർത്തുക;
		}

		എങ്കിൽ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			നിർത്തുക;
		}
		എങ്കിൽ (bind(sock, (ഘടന sockaddr *)&sunaddr,
		    വലുപ്പം(sunaddr)) == -1) {
			എങ്കിൽ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				തുടരുക;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			നിർത്തുക;
		}
		എങ്കിൽ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			നിർത്തുക;
		}
		good = 1;
	}
	umask(prev_mask);
	എങ്കിൽ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} അല്ലെങ്കിൽ എങ്കിൽ (sock != -1) {
		close(sock);
		sock = -1;
	}
	തിരികെ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
agent_listener_shared(സ്ഥിരം അക്ഷരം *parent_dir, pid_t pid, സ്ഥിരം അക്ഷരം *tag,
    പൂർണ്ണസംഖ്യ *sockp, അക്ഷരം **pathp, അക്ഷരം **dirp)
{
	അക്ഷരം *dir = ശൂന്യ, *path = ശൂന്യ;
	പൂർണ്ണസംഖ്യ sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = ശൂന്യ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	എങ്കിൽ (mkdtemp(dir) == ശൂന്യ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		പോകുക out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	എങ്കിൽ ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		എങ്കിൽ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		പോകുക out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = ശൂന്യ; /* transferred */
	*pathp = path;
	path = ശൂന്യ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	സ്വതന്ത്രം(dir);
	സ്വതന്ത്രം(path);
	തിരികെ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
agent_listener_user(സ്ഥിരം അക്ഷരം *dir, pid_t pid, സ്ഥിരം അക്ഷരം *tag,
    പൂർണ്ണസംഖ്യ *sockp, അക്ഷരം **pathp)
{
	അക്ഷരം *hostnamehash = ശൂന്യ, *path = ശൂന്യ;
	പൂർണ്ണസംഖ്യ sock, ret = -1;

	എങ്കിൽ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ശൂന്യ)
		തിരികെ -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	എങ്കിൽ (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		പോകുക out;
	}
	എങ്കിൽ ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		പോകുക out;
	}
	/* Success */
	*pathp = path;
	path = ശൂന്യ; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	സ്വതന്ത്രം(hostnamehash);
	സ്വതന്ത്രം(path);
	തിരികെ ret;
}

സ്ഥിതം അക്ഷരം *
expand_pathspec(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *username,
    uid_t uid, സ്ഥിരം അക്ഷരം *homedir)
{
	അക്ഷരം *uidbuf = ശൂന്യ, *dir = ശൂന്യ, *tmp = ശൂന്യ;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	എങ്കിൽ ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, ശൂന്യ)) == ശൂന്യ) {
		error_f("failed to percent-expand agent socket directory");
		പോകുക out;
	}
	എങ്കിൽ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		പോകുക out;
	}
	എങ്കിൽ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		സ്വതന്ത്രം(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	സ്വതന്ത്രം(uidbuf);
	സ്വതന്ത്രം(tmp);
	തിരികെ dir;
}

പൂർണ്ണസംഖ്യ
agent_listener(സ്ഥിരം അക്ഷരം *pathspec, സ്ഥിരം അക്ഷരം *username, uid_t uid,
    സ്ഥിരം അക്ഷരം *homedir, pid_t pid, സ്ഥിരം അക്ഷരം *tag, പൂർണ്ണസംഖ്യ *sockp,
    അക്ഷരം **pathp, അക്ഷരം **dirp)
{
	പൂർണ്ണസംഖ്യ sock = -1, ret = -1;
	അക്ഷരം *path = ശൂന്യ, *dir = ശൂന്യ;

	*sockp = -1;
	*pathp = *dirp = ശൂന്യ;

	എങ്കിൽ (pathspec == ശൂന്യ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		തിരികെ -1;
	}
	എങ്കിൽ (strncmp(pathspec, "shared:", 7) == 0) {
		എങ്കിൽ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			പോകുക out;
		}
		എങ്കിൽ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ശൂന്യ) {
			/* Error already logged */
			പോകുക out;
		}
		എങ്കിൽ (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			പോകുക out;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(pathspec, "user:", 5) == 0) {
		എങ്കിൽ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ശൂന്യ) {
			/* Error already logged */
			പോകുക out;
		}
		എങ്കിൽ (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			പോകുക out;
		}
	} അല്ലെങ്കിൽ {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		പോകുക out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = ശൂന്യ; /* transferred */
 out:
	സ്വതന്ത്രം(path);
	സ്വതന്ത്രം(dir);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
agent_listener_cleanup(സ്ഥിരം അക്ഷരം *pathspec, സ്ഥിരം അക്ഷരം *sockpath,
    സ്ഥിരം അക്ഷരം *sockdir)
{
	എങ്കിൽ (sockpath == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		തിരികെ -1;
	}
	debug3_f("removed socket %s", sockpath);

	എങ്കിൽ (pathspec == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (strncmp(pathspec, "shared:", 7) == 0 && sockdir != ശൂന്യ) {
		എങ്കിൽ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			തിരികെ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
socket_is_stale(സ്ഥിരം അക്ഷരം *path)
{
	പൂർണ്ണസംഖ്യ fd, r;
	ഘടന sockaddr_un sunaddr;
	socklen_t l = വലുപ്പം(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', വലുപ്പം(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	എങ്കിൽ (strlcpy(sunaddr.sun_path, path,
	    വലുപ്പം(sunaddr.sun_path)) >= വലുപ്പം(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		തിരികെ 0;
	}
	എങ്കിൽ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		തിരികെ 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	എങ്കിൽ (connect(fd, (ഘടന sockaddr *)&sunaddr, വലുപ്പം(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		തിരികെ 1;
	}
	എങ്കിൽ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		തിരികെ 0;
	}
	എങ്കിൽ (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		തിരികെ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	തിരികെ 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

ശൂന്യം
agent_cleanup_stale(സ്ഥിരം അക്ഷരം *pathspec, സ്ഥിരം അക്ഷരം *username, uid_t uid,
    സ്ഥിരം അക്ഷരം *homedir, പൂർണ്ണസംഖ്യ ignore_hosthash)
{
	DIR *d = ശൂന്യ;
	ഘടന dirent *dp;
	ഘടന stat sb;
	അക്ഷരം *prefix = ശൂന്യ, *dir = ശൂന്യ, *path;
	ഘടന timespec now, sub, *mtimp = ശൂന്യ;

	/* Only clean up user socket directories */
	എങ്കിൽ (pathspec == ശൂന്യ || strncmp(pathspec, "user:", 5) != 0)
		തിരികെ;

	എങ്കിൽ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ശൂന്യ)
		തിരികെ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	എങ്കിൽ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		പോകുക out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	എങ്കിൽ (!ignore_hosthash) {
		എങ്കിൽ ((path = agent_hostname_hash()) == ശൂന്യ) {
			error_f("couldn't get hostname hash");
			പോകുക out;
		}
		xasprintf(&prefix, "s.%s.", path);
		സ്വതന്ത്രം(path);
	}

	എങ്കിൽ ((d = opendir(dir)) == ശൂന്യ) {
		എങ്കിൽ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		പോകുക out;
	}
	ആകുമ്പോൾ ((dp = readdir(d)) != ശൂന്യ) {
#ifdef HAVE_DIRENT_D_TYPE
		എങ്കിൽ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			തുടരുക;
#endif
		എങ്കിൽ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			തുടരുക;
		}
		എങ്കിൽ (!S_ISSOCK(sb.st_mode))
			തുടരുക;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#അല്ലെങ്കിൽ
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		എങ്കിൽ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			തുടരുക;
		}
		എങ്കിൽ (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			തുടരുക;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		എങ്കിൽ (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		സ്വതന്ത്രം(path);
	}
 out:
	എങ്കിൽ (d != ശൂന്യ)
		closedir(d);
	സ്വതന്ത്രം(dir);
	സ്വതന്ത്രം(prefix);
}

#undef unlinkat
#undef fstatat
