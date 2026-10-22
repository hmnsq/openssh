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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <libgen.h>

#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
நிலையான மாறிலி எழுத்து presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
நிலையான எழுத்து *
hostname_hash(size_t len)
{
	எழுத்து hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	முழு r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	எனில் (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		திரும்பு வெற்று;
	}
	எனில் (gethostname(hostname, அளவு(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		திரும்பு வெற்று;
	}
	எனில் ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, அளவு(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		திரும்பு வெற்று;
	}
	memset(p, '\0', அளவு(p));
	க்கு (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (அளவு(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	திரும்பு xstrdup(p);
}

நிலையான எழுத்து *
agent_hostname_hash(வெறுமை)
{
	திரும்பு hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
நிலையான முழு
unix_listener_tmp(எழுத்து *path, முழு backlog)
{
	கட்டமைப்பு sockaddr_un sunaddr;
	முழு good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	போது (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, அளவு(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	க்கு (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		க்கு (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(அளவு(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		எனில் (strlcpy(sunaddr.sun_path, path,
		    அளவு(sunaddr.sun_path)) >= அளவு(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			நிறுத்து;
		}

		எனில் ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			நிறுத்து;
		}
		எனில் (bind(sock, (கட்டமைப்பு sockaddr *)&sunaddr,
		    அளவு(sunaddr)) == -1) {
			எனில் (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				தொடர்;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			நிறுத்து;
		}
		எனில் (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			நிறுத்து;
		}
		good = 1;
	}
	umask(prev_mask);
	எனில் (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} இல்லையெனில் எனில் (sock != -1) {
		close(sock);
		sock = -1;
	}
	திரும்பு sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
நிலையான முழு
agent_listener_shared(மாறிலி எழுத்து *parent_dir, pid_t pid, மாறிலி எழுத்து *tag,
    முழு *sockp, எழுத்து **pathp, எழுத்து **dirp)
{
	எழுத்து *dir = வெற்று, *path = வெற்று;
	முழு sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = வெற்று;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	எனில் (mkdtemp(dir) == வெற்று) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		செல் out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	எனில் ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		எனில் (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		செல் out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = வெற்று; /* transferred */
	*pathp = path;
	path = வெற்று; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	விடுவி(dir);
	விடுவி(path);
	திரும்பு ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
நிலையான முழு
agent_listener_user(மாறிலி எழுத்து *dir, pid_t pid, மாறிலி எழுத்து *tag,
    முழு *sockp, எழுத்து **pathp)
{
	எழுத்து *hostnamehash = வெற்று, *path = வெற்று;
	முழு sock, ret = -1;

	எனில் ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == வெற்று)
		திரும்பு -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	எனில் (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		செல் out;
	}
	எனில் ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		செல் out;
	}
	/* Success */
	*pathp = path;
	path = வெற்று; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	விடுவி(hostnamehash);
	விடுவி(path);
	திரும்பு ret;
}

நிலையான எழுத்து *
expand_pathspec(மாறிலி எழுத்து *path, மாறிலி எழுத்து *username,
    uid_t uid, மாறிலி எழுத்து *homedir)
{
	எழுத்து *uidbuf = வெற்று, *dir = வெற்று, *tmp = வெற்று;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	எனில் ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, வெற்று)) == வெற்று) {
		error_f("failed to percent-expand agent socket directory");
		செல் out;
	}
	எனில் (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		செல் out;
	}
	எனில் (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		விடுவி(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	விடுவி(uidbuf);
	விடுவி(tmp);
	திரும்பு dir;
}

முழு
agent_listener(மாறிலி எழுத்து *pathspec, மாறிலி எழுத்து *username, uid_t uid,
    மாறிலி எழுத்து *homedir, pid_t pid, மாறிலி எழுத்து *tag, முழு *sockp,
    எழுத்து **pathp, எழுத்து **dirp)
{
	முழு sock = -1, ret = -1;
	எழுத்து *path = வெற்று, *dir = வெற்று;

	*sockp = -1;
	*pathp = *dirp = வெற்று;

	எனில் (pathspec == வெற்று || pathspec[0] == '\0') {
		error_f("no agent path specified");
		திரும்பு -1;
	}
	எனில் (strncmp(pathspec, "shared:", 7) == 0) {
		எனில் (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			செல் out;
		}
		எனில் ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == வெற்று) {
			/* Error already logged */
			செல் out;
		}
		எனில் (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			செல் out;
		}
	} இல்லையெனில் எனில் (strncmp(pathspec, "user:", 5) == 0) {
		எனில் ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == வெற்று) {
			/* Error already logged */
			செல் out;
		}
		எனில் (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			செல் out;
		}
	} இல்லையெனில் {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		செல் out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = வெற்று; /* transferred */
 out:
	விடுவி(path);
	விடுவி(dir);
	திரும்பு ret;
}

முழு
agent_listener_cleanup(மாறிலி எழுத்து *pathspec, மாறிலி எழுத்து *sockpath,
    மாறிலி எழுத்து *sockdir)
{
	எனில் (sockpath == வெற்று)
		திரும்பு 0;
	எனில் (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		திரும்பு -1;
	}
	debug3_f("removed socket %s", sockpath);

	எனில் (pathspec == வெற்று)
		திரும்பு 0;
	எனில் (strncmp(pathspec, "shared:", 7) == 0 && sockdir != வெற்று) {
		எனில் (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			திரும்பு -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	திரும்பு 0;
}

நிலையான முழு
socket_is_stale(மாறிலி எழுத்து *path)
{
	முழு fd, r;
	கட்டமைப்பு sockaddr_un sunaddr;
	socklen_t l = அளவு(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', அளவு(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	எனில் (strlcpy(sunaddr.sun_path, path,
	    அளவு(sunaddr.sun_path)) >= அளவு(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		திரும்பு 0;
	}
	எனில் ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		திரும்பு 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	எனில் (connect(fd, (கட்டமைப்பு sockaddr *)&sunaddr, அளவு(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		திரும்பு 1;
	}
	எனில் (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		திரும்பு 0;
	}
	எனில் (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		திரும்பு 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	திரும்பு 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

வெறுமை
agent_cleanup_stale(மாறிலி எழுத்து *pathspec, மாறிலி எழுத்து *username, uid_t uid,
    மாறிலி எழுத்து *homedir, முழு ignore_hosthash)
{
	DIR *d = வெற்று;
	கட்டமைப்பு dirent *dp;
	கட்டமைப்பு stat sb;
	எழுத்து *prefix = வெற்று, *dir = வெற்று, *path;
	கட்டமைப்பு timespec now, sub, *mtimp = வெற்று;

	/* Only clean up user socket directories */
	எனில் (pathspec == வெற்று || strncmp(pathspec, "user:", 5) != 0)
		திரும்பு;

	எனில் ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == வெற்று)
		திரும்பு; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	எனில் (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		செல் out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	எனில் (!ignore_hosthash) {
		எனில் ((path = agent_hostname_hash()) == வெற்று) {
			error_f("couldn't get hostname hash");
			செல் out;
		}
		xasprintf(&prefix, "s.%s.", path);
		விடுவி(path);
	}

	எனில் ((d = opendir(dir)) == வெற்று) {
		எனில் (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		செல் out;
	}
	போது ((dp = readdir(d)) != வெற்று) {
#ifdef HAVE_DIRENT_D_TYPE
		எனில் (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			தொடர்;
#endif
		எனில் (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			தொடர்;
		}
		எனில் (!S_ISSOCK(sb.st_mode))
			தொடர்;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#இல்லையெனில்
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		எனில் (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			தொடர்;
		}
		எனில் (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			தொடர்;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		எனில் (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		விடுவி(path);
	}
 out:
	எனில் (d != வெற்று)
		closedir(d);
	விடுவி(dir);
	விடுவி(prefix);
}

#undef unlinkat
#undef fstatat
