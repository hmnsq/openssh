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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <libgen.h>

#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
સ્થિર અચલ અક્ષર presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
સ્થિર અક્ષર *
hostname_hash(size_t len)
{
	અક્ષર hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	પૂર્ણાંક r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	જો (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		પાછા ખાલી;
	}
	જો (gethostname(hostname, કદ(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		પાછા ખાલી;
	}
	જો ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, કદ(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		પાછા ખાલી;
	}
	memset(p, '\0', કદ(p));
	માટે (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (કદ(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	પાછા xstrdup(p);
}

સ્થિર અક્ષર *
agent_hostname_hash(શૂન્ય)
{
	પાછા hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
સ્થિર પૂર્ણાંક
unix_listener_tmp(અક્ષર *path, પૂર્ણાંક backlog)
{
	સંરચના sockaddr_un sunaddr;
	પૂર્ણાંક good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	જ્યારે (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, કદ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	માટે (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		માટે (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(કદ(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		જો (strlcpy(sunaddr.sun_path, path,
		    કદ(sunaddr.sun_path)) >= કદ(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			તોડો;
		}

		જો ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			તોડો;
		}
		જો (bind(sock, (સંરચના sockaddr *)&sunaddr,
		    કદ(sunaddr)) == -1) {
			જો (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				ચાલુ;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			તોડો;
		}
		જો (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			તોડો;
		}
		good = 1;
	}
	umask(prev_mask);
	જો (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} નહીંતર જો (sock != -1) {
		close(sock);
		sock = -1;
	}
	પાછા sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
સ્થિર પૂર્ણાંક
agent_listener_shared(અચલ અક્ષર *parent_dir, pid_t pid, અચલ અક્ષર *tag,
    પૂર્ણાંક *sockp, અક્ષર **pathp, અક્ષર **dirp)
{
	અક્ષર *dir = ખાલી, *path = ખાલી;
	પૂર્ણાંક sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = ખાલી;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	જો (mkdtemp(dir) == ખાલી) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		જાઓ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	જો ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		જો (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		જાઓ out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = ખાલી; /* transferred */
	*pathp = path;
	path = ખાલી; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	મુક્ત(dir);
	મુક્ત(path);
	પાછા ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
સ્થિર પૂર્ણાંક
agent_listener_user(અચલ અક્ષર *dir, pid_t pid, અચલ અક્ષર *tag,
    પૂર્ણાંક *sockp, અક્ષર **pathp)
{
	અક્ષર *hostnamehash = ખાલી, *path = ખાલી;
	પૂર્ણાંક sock, ret = -1;

	જો ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ખાલી)
		પાછા -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	જો (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		જાઓ out;
	}
	જો ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		જાઓ out;
	}
	/* Success */
	*pathp = path;
	path = ખાલી; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	મુક્ત(hostnamehash);
	મુક્ત(path);
	પાછા ret;
}

સ્થિર અક્ષર *
expand_pathspec(અચલ અક્ષર *path, અચલ અક્ષર *username,
    uid_t uid, અચલ અક્ષર *homedir)
{
	અક્ષર *uidbuf = ખાલી, *dir = ખાલી, *tmp = ખાલી;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	જો ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, ખાલી)) == ખાલી) {
		error_f("failed to percent-expand agent socket directory");
		જાઓ out;
	}
	જો (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		જાઓ out;
	}
	જો (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		મુક્ત(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	મુક્ત(uidbuf);
	મુક્ત(tmp);
	પાછા dir;
}

પૂર્ણાંક
agent_listener(અચલ અક્ષર *pathspec, અચલ અક્ષર *username, uid_t uid,
    અચલ અક્ષર *homedir, pid_t pid, અચલ અક્ષર *tag, પૂર્ણાંક *sockp,
    અક્ષર **pathp, અક્ષર **dirp)
{
	પૂર્ણાંક sock = -1, ret = -1;
	અક્ષર *path = ખાલી, *dir = ખાલી;

	*sockp = -1;
	*pathp = *dirp = ખાલી;

	જો (pathspec == ખાલી || pathspec[0] == '\0') {
		error_f("no agent path specified");
		પાછા -1;
	}
	જો (strncmp(pathspec, "shared:", 7) == 0) {
		જો (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			જાઓ out;
		}
		જો ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ખાલી) {
			/* Error already logged */
			જાઓ out;
		}
		જો (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			જાઓ out;
		}
	} નહીંતર જો (strncmp(pathspec, "user:", 5) == 0) {
		જો ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ખાલી) {
			/* Error already logged */
			જાઓ out;
		}
		જો (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			જાઓ out;
		}
	} નહીંતર {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		જાઓ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = ખાલી; /* transferred */
 out:
	મુક્ત(path);
	મુક્ત(dir);
	પાછા ret;
}

પૂર્ણાંક
agent_listener_cleanup(અચલ અક્ષર *pathspec, અચલ અક્ષર *sockpath,
    અચલ અક્ષર *sockdir)
{
	જો (sockpath == ખાલી)
		પાછા 0;
	જો (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		પાછા -1;
	}
	debug3_f("removed socket %s", sockpath);

	જો (pathspec == ખાલી)
		પાછા 0;
	જો (strncmp(pathspec, "shared:", 7) == 0 && sockdir != ખાલી) {
		જો (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			પાછા -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
socket_is_stale(અચલ અક્ષર *path)
{
	પૂર્ણાંક fd, r;
	સંરચના sockaddr_un sunaddr;
	socklen_t l = કદ(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', કદ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	જો (strlcpy(sunaddr.sun_path, path,
	    કદ(sunaddr.sun_path)) >= કદ(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		પાછા 0;
	}
	જો ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		પાછા 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	જો (connect(fd, (સંરચના sockaddr *)&sunaddr, કદ(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		પાછા 1;
	}
	જો (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		પાછા 0;
	}
	જો (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		પાછા 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	પાછા 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

શૂન્ય
agent_cleanup_stale(અચલ અક્ષર *pathspec, અચલ અક્ષર *username, uid_t uid,
    અચલ અક્ષર *homedir, પૂર્ણાંક ignore_hosthash)
{
	DIR *d = ખાલી;
	સંરચના dirent *dp;
	સંરચના stat sb;
	અક્ષર *prefix = ખાલી, *dir = ખાલી, *path;
	સંરચના timespec now, sub, *mtimp = ખાલી;

	/* Only clean up user socket directories */
	જો (pathspec == ખાલી || strncmp(pathspec, "user:", 5) != 0)
		પાછા;

	જો ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ખાલી)
		પાછા; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	જો (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		જાઓ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	જો (!ignore_hosthash) {
		જો ((path = agent_hostname_hash()) == ખાલી) {
			error_f("couldn't get hostname hash");
			જાઓ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		મુક્ત(path);
	}

	જો ((d = opendir(dir)) == ખાલી) {
		જો (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		જાઓ out;
	}
	જ્યારે ((dp = readdir(d)) != ખાલી) {
#ifdef HAVE_DIRENT_D_TYPE
		જો (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ચાલુ;
#endif
		જો (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ચાલુ;
		}
		જો (!S_ISSOCK(sb.st_mode))
			ચાલુ;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#નહીંતર
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		જો (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ચાલુ;
		}
		જો (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ચાલુ;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		જો (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		મુક્ત(path);
	}
 out:
	જો (d != ખાલી)
		closedir(d);
	મુક્ત(dir);
	મુક્ત(prefix);
}

#undef unlinkat
#undef fstatat
