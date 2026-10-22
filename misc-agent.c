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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <libgen.h>

#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
স্থির ধ্রুবক অক্ষর presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
স্থির অক্ষর *
hostname_hash(আকার_t len)
{
	অক্ষর hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	পূর্ণসংখ্যা r;
	আকার_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	যদি (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ফেরত ফাঁকা;
	}
	যদি (gethostname(hostname, আকার(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ফেরত ফাঁকা;
	}
	যদি ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, আকার(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ফেরত ফাঁকা;
	}
	memset(p, '\0', আকার(p));
	জন্য (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (আকার(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ফেরত xstrdup(p);
}

স্থির অক্ষর *
agent_hostname_hash(শূন্য)
{
	ফেরত hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
স্থির পূর্ণসংখ্যা
unix_listener_tmp(অক্ষর *path, পূর্ণসংখ্যা backlog)
{
	কাঠামো sockaddr_un sunaddr;
	পূর্ণসংখ্যা good, sock = -1;
	আকার_t i, xstart;
	mode_t পূর্ব_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	যখন (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, আকার(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	পূর্ব_mask = umask(0177);
	জন্য (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		জন্য (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(আকার(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		যদি (strlcpy(sunaddr.sun_path, path,
		    আকার(sunaddr.sun_path)) >= আকার(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			বিরতি;
		}

		যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			বিরতি;
		}
		যদি (bind(sock, (কাঠামো sockaddr *)&sunaddr,
		    আকার(sunaddr)) == -1) {
			যদি (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				চালু;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			বিরতি;
		}
		যদি (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			বিরতি;
		}
		good = 1;
	}
	umask(পূর্ব_mask);
	যদি (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} অন্যথা যদি (sock != -1) {
		close(sock);
		sock = -1;
	}
	ফেরত sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
স্থির পূর্ণসংখ্যা
agent_listener_shared(ধ্রুবক অক্ষর *parent_dir, pid_t pid, ধ্রুবক অক্ষর *tag,
    পূর্ণসংখ্যা *sockp, অক্ষর **pathp, অক্ষর **dirp)
{
	অক্ষর *dir = ফাঁকা, *path = ফাঁকা;
	পূর্ণসংখ্যা sock, ret = -1;
	mode_t পূর্ব_mask;

	*pathp = *dirp = ফাঁকা;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	যদি (mkdtemp(dir) == ফাঁকা) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		যাও out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	পূর্ব_mask = umask(0177);
	যদি ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(পূর্ব_mask);
		যদি (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		যাও out;
	}
	umask(পূর্ব_mask);

	/* Success */
	*dirp = dir;
	dir = ফাঁকা; /* transferred */
	*pathp = path;
	path = ফাঁকা; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	মুক্ত(dir);
	মুক্ত(path);
	ফেরত ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
স্থির পূর্ণসংখ্যা
agent_listener_user(ধ্রুবক অক্ষর *dir, pid_t pid, ধ্রুবক অক্ষর *tag,
    পূর্ণসংখ্যা *sockp, অক্ষর **pathp)
{
	অক্ষর *hostnamehash = ফাঁকা, *path = ফাঁকা;
	পূর্ণসংখ্যা sock, ret = -1;

	যদি ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ফাঁকা)
		ফেরত -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	যদি (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		যাও out;
	}
	যদি ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		যাও out;
	}
	/* Success */
	*pathp = path;
	path = ফাঁকা; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	মুক্ত(hostnamehash);
	মুক্ত(path);
	ফেরত ret;
}

স্থির অক্ষর *
expand_pathspec(ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *username,
    uid_t uid, ধ্রুবক অক্ষর *homedir)
{
	অক্ষর *uidbuf = ফাঁকা, *dir = ফাঁকা, *tmp = ফাঁকা;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	যদি ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, ফাঁকা)) == ফাঁকা) {
		error_f("failed to percent-expand agent socket directory");
		যাও out;
	}
	যদি (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		যাও out;
	}
	যদি (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		মুক্ত(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 out:
	মুক্ত(uidbuf);
	মুক্ত(tmp);
	ফেরত dir;
}

পূর্ণসংখ্যা
agent_listener(ধ্রুবক অক্ষর *pathspec, ধ্রুবক অক্ষর *username, uid_t uid,
    ধ্রুবক অক্ষর *homedir, pid_t pid, ধ্রুবক অক্ষর *tag, পূর্ণসংখ্যা *sockp,
    অক্ষর **pathp, অক্ষর **dirp)
{
	পূর্ণসংখ্যা sock = -1, ret = -1;
	অক্ষর *path = ফাঁকা, *dir = ফাঁকা;

	*sockp = -1;
	*pathp = *dirp = ফাঁকা;

	যদি (pathspec == ফাঁকা || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ফেরত -1;
	}
	যদি (strncmp(pathspec, "shared:", 7) == 0) {
		যদি (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			যাও out;
		}
		যদি ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ফাঁকা) {
			/* Error already logged */
			যাও out;
		}
		যদি (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			যাও out;
		}
	} অন্যথা যদি (strncmp(pathspec, "user:", 5) == 0) {
		যদি ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ফাঁকা) {
			/* Error already logged */
			যাও out;
		}
		যদি (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			যাও out;
		}
	} অন্যথা {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		যাও out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = ফাঁকা; /* transferred */
 out:
	মুক্ত(path);
	মুক্ত(dir);
	ফেরত ret;
}

পূর্ণসংখ্যা
agent_listener_cleanup(ধ্রুবক অক্ষর *pathspec, ধ্রুবক অক্ষর *sockpath,
    ধ্রুবক অক্ষর *sockdir)
{
	যদি (sockpath == ফাঁকা)
		ফেরত 0;
	যদি (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ফেরত -1;
	}
	debug3_f("removed socket %s", sockpath);

	যদি (pathspec == ফাঁকা)
		ফেরত 0;
	যদি (strncmp(pathspec, "shared:", 7) == 0 && sockdir != ফাঁকা) {
		যদি (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ফেরত -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
socket_is_stale(ধ্রুবক অক্ষর *path)
{
	পূর্ণসংখ্যা fd, r;
	কাঠামো sockaddr_un sunaddr;
	socklen_t l = আকার(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', আকার(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	যদি (strlcpy(sunaddr.sun_path, path,
	    আকার(sunaddr.sun_path)) >= আকার(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ফেরত 0;
	}
	যদি ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ফেরত 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	যদি (connect(fd, (কাঠামো sockaddr *)&sunaddr, আকার(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ফেরত 1;
	}
	যদি (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ফেরত 0;
	}
	যদি (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ফেরত 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ফেরত 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

শূন্য
agent_cleanup_stale(ধ্রুবক অক্ষর *pathspec, ধ্রুবক অক্ষর *username, uid_t uid,
    ধ্রুবক অক্ষর *homedir, পূর্ণসংখ্যা ignore_hosthash)
{
	DIR *d = ফাঁকা;
	কাঠামো dirent *dp;
	কাঠামো stat sb;
	অক্ষর *prefix = ফাঁকা, *dir = ফাঁকা, *path;
	কাঠামো timespec now, sub, *mtimp = ফাঁকা;

	/* Only clean up user socket directories */
	যদি (pathspec == ফাঁকা || strncmp(pathspec, "user:", 5) != 0)
		ফেরত;

	যদি ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ফাঁকা)
		ফেরত; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	যদি (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		যাও out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	যদি (!ignore_hosthash) {
		যদি ((path = agent_hostname_hash()) == ফাঁকা) {
			error_f("couldn't get hostname hash");
			যাও out;
		}
		xasprintf(&prefix, "s.%s.", path);
		মুক্ত(path);
	}

	যদি ((d = opendir(dir)) == ফাঁকা) {
		যদি (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		যাও out;
	}
	যখন ((dp = readdir(d)) != ফাঁকা) {
#ifdef HAVE_DIRENT_D_TYPE
		যদি (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			চালু;
#endif
		যদি (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			চালু;
		}
		যদি (!S_ISSOCK(sb.st_mode))
			চালু;
#ifdef HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#অন্যথা
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#endif
		যদি (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			চালু;
		}
		যদি (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			চালু;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		যদি (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		মুক্ত(path);
	}
 out:
	যদি (d != ফাঁকা)
		closedir(d);
	মুক্ত(dir);
	মুক্ত(prefix);
}

#undef unlinkat
#undef fstatat
