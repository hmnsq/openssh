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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <libgen.h>

#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
ସ୍ଥିର ଅକ୍ଷର *
hostname_hash(size_t len)
{
	ଅକ୍ଷର hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	ଯଦି (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (gethostname(hostname, ଆକାର(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, ଆକାର(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	memset(p, '\0', ଆକାର(p));
	ପାଇଁ (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (ଆକାର(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ଫେରନ୍ତୁ xstrdup(p);
}

ସ୍ଥିର ଅକ୍ଷର *
agent_hostname_hash(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
unix_listener_tmp(ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା backlog)
{
	ସଂରଚନା sockaddr_un sunaddr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	ଯେତେବେଳେ (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, ଆକାର(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	ପାଇଁ (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		ପାଇଁ (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(ଆକାର(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		ଯଦି (strlcpy(sunaddr.sun_path, path,
		    ଆକାର(sunaddr.sun_path)) >= ଆକାର(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			ଭାଙ୍ଗ;
		}

		ଯଦି ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ଭାଙ୍ଗ;
		}
		ଯଦି (bind(sock, (ସଂରଚନା sockaddr *)&sunaddr,
		    ଆକାର(sunaddr)) == -1) {
			ଯଦି (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				ଜାରି;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			ଭାଙ୍ଗ;
		}
		ଯଦି (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			ଭାଙ୍ଗ;
		}
		good = 1;
	}
	umask(prev_mask);
	ଯଦି (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} ଅନ୍ୟଥା ଯଦି (sock != -1) {
		close(sock);
		sock = -1;
	}
	ଫେରନ୍ତୁ sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
agent_listener_shared(ଅଚଳ ଅକ୍ଷର *parent_dir, pid_t pid, ଅଚଳ ଅକ୍ଷର *tag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sockp, ଅକ୍ଷର **pathp, ଅକ୍ଷର **dirp)
{
	ଅକ୍ଷର *dir = ଖାଲି, *path = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = ଖାଲି;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	ଯଦି (mkdtemp(dir) == ଖାଲି) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		ଯାଅ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	ଯଦି ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		ଯଦି (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		ଯାଅ out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = ଖାଲି; /* transferred */
	*pathp = path;
	path = ଖାଲି; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	ମୁକ୍ତ(dir);
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
agent_listener_user(ଅଚଳ ଅକ୍ଷର *dir, pid_t pid, ଅଚଳ ଅକ୍ଷର *tag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sockp, ଅକ୍ଷର **pathp)
{
	ଅକ୍ଷର *hostnamehash = ଖାଲି, *path = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ret = -1;

	ଯଦି ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	ଯଦି (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		ଯାଅ out;
	}
	ଯଦି ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		ଯାଅ out;
	}
	/* Success */
	*pathp = path;
	path = ଖାଲି; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	ମୁକ୍ତ(hostnamehash);
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅକ୍ଷର *
expand_pathspec(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *username,
    uid_t uid, ଅଚଳ ଅକ୍ଷର *homedir)
{
	ଅକ୍ଷର *uidbuf = ଖାଲି, *dir = ଖାଲି, *tmp = ଖାଲି;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	ଯଦି ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, ଖାଲି)) == ଖାଲି) {
		error_f("failed to percent-expand agent socket directory");
		ଯାଅ out;
	}
	ଯଦି (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		ଯାଅ out;
	}
	ଯଦି (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		ମୁକ୍ତ(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	ମୁକ୍ତ(uidbuf);
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ dir;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
agent_listener(ଅଚଳ ଅକ୍ଷର *pathspec, ଅଚଳ ଅକ୍ଷର *username, uid_t uid,
    ଅଚଳ ଅକ୍ଷର *homedir, pid_t pid, ଅଚଳ ଅକ୍ଷର *tag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sockp,
    ଅକ୍ଷର **pathp, ଅକ୍ଷର **dirp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = -1, ret = -1;
	ଅକ୍ଷର *path = ଖାଲି, *dir = ଖାଲି;

	*sockp = -1;
	*pathp = *dirp = ଖାଲି;

	ଯଦି (pathspec == ଖାଲି || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (strncmp(pathspec, "shared:", 7) == 0) {
		ଯଦି (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			ଯାଅ out;
		}
		ଯଦି ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ଖାଲି) {
			/* Error already logged */
			ଯାଅ out;
		}
		ଯଦି (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା ଯଦି (strncmp(pathspec, "user:", 5) == 0) {
		ଯଦି ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ଖାଲି) {
			/* Error already logged */
			ଯାଅ out;
		}
		ଯଦି (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		ଯାଅ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = ଖାଲି; /* transferred */
 out:
	ମୁକ୍ତ(path);
	ମୁକ୍ତ(dir);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
agent_listener_cleanup(ଅଚଳ ଅକ୍ଷର *pathspec, ଅଚଳ ଅକ୍ଷର *sockpath,
    ଅଚଳ ଅକ୍ଷର *sockdir)
{
	ଯଦି (sockpath == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	debug3_f("removed socket %s", sockpath);

	ଯଦି (pathspec == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strncmp(pathspec, "shared:", 7) == 0 && sockdir != ଖାଲି) {
		ଯଦି (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ଫେରନ୍ତୁ -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
socket_is_stale(ଅଚଳ ଅକ୍ଷର *path)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, r;
	ସଂରଚନା sockaddr_un sunaddr;
	socklen_t l = ଆକାର(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', ଆକାର(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ଯଦି (strlcpy(sunaddr.sun_path, path,
	    ଆକାର(sunaddr.sun_path)) >= ଆକାର(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ଫେରନ୍ତୁ 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ଯଦି (connect(fd, (ସଂରଚନା sockaddr *)&sunaddr, ଆକାର(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ଫେରନ୍ତୁ 1;
	}
	ଯଦି (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ଫେରନ୍ତୁ 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ଫେରନ୍ତୁ 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

ଶୂନ୍ୟ
agent_cleanup_stale(ଅଚଳ ଅକ୍ଷର *pathspec, ଅଚଳ ଅକ୍ଷର *username, uid_t uid,
    ଅଚଳ ଅକ୍ଷର *homedir, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ignore_hosthash)
{
	DIR *d = ଖାଲି;
	ସଂରଚନା dirent *dp;
	ସଂରଚନା stat sb;
	ଅକ୍ଷର *prefix = ଖାଲି, *dir = ଖାଲି, *path;
	ସଂରଚନା timespec now, sub, *mtimp = ଖାଲି;

	/* Only clean up user socket directories */
	ଯଦି (pathspec == ଖାଲି || strncmp(pathspec, "user:", 5) != 0)
		ଫେରନ୍ତୁ;

	ଯଦି ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ଖାଲି)
		ଫେରନ୍ତୁ; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ଯଦି (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		ଯାଅ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ଯଦି (!ignore_hosthash) {
		ଯଦି ((path = agent_hostname_hash()) == ଖାଲି) {
			error_f("couldn't get hostname hash");
			ଯାଅ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		ମୁକ୍ତ(path);
	}

	ଯଦି ((d = opendir(dir)) == ଖାଲି) {
		ଯଦି (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		ଯାଅ out;
	}
	ଯେତେବେଳେ ((dp = readdir(d)) != ଖାଲି) {
#ifdef HAVE_DIRENT_D_TYPE
		ଯଦି (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			ଜାରି;
#endif
		ଯଦି (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			ଜାରି;
		}
		ଯଦି (!S_ISSOCK(sb.st_mode))
			ଜାରି;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#ଅନ୍ୟଥା
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		ଯଦି (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			ଜାରି;
		}
		ଯଦି (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			ଜାରି;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		ଯଦି (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		ମୁକ୍ତ(path);
	}
 out:
	ଯଦି (d != ଖାଲି)
		closedir(d);
	ମୁକ୍ତ(dir);
	ମୁକ୍ତ(prefix);
}

#undef unlinkat
#undef fstatat
