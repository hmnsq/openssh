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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/un.h>

#অন্তর্ভাৱ <dirent.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <time.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <libgen.h>

#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#define SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
স্থির ধ্রুৱ ৱর্ণ presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
স্থির ৱর্ণ *
hostname_hash(size_t len)
{
	ৱর্ণ hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	পূর্ণাঙ্ক r;
	size_t l, i;

	l = ssh_digest_bytes(SSH_DIGEST_SHA512);
	যদি (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		ঘূৰাই রিক্ত;
	}
	যদি (gethostname(hostname, পরিমাণ(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		ঘূৰাই রিক্ত;
	}
	যদি ((r = ssh_digest_memory(SSH_DIGEST_SHA512,
	    hostname, strlen(hostname), hash, পরিমাণ(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		ঘূৰাই রিক্ত;
	}
	memset(p, '\0', পরিমাণ(p));
	বাবে (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (পরিমাণ(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	ঘূৰাই xstrdup(p);
}

স্থির ৱর্ণ *
agent_hostname_hash(শূন্য)
{
	ঘূৰাই hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
স্থির পূর্ণাঙ্ক
unix_listener_tmp(ৱর্ণ *path, পূর্ণাঙ্ক backlog)
{
	সংরচনা sockaddr_un sunaddr;
	পূর্ণাঙ্ক good, sock = -1;
	size_t i, xstart;
	mode_t prev_mask;

	/* Find first 'X' template character back from end of string */
	xstart = strlen(path);
	যেতিয়ালৈ (xstart > 0 && path[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, পরিমাণ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_mask = umask(0177);
	বাবে (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		বাবে (i = xstart; path[i] != '\0'; i++) {
			path[i] = presentation_chars[
			    arc4random_uniform(পরিমাণ(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", path);

		যদি (strlcpy(sunaddr.sun_path, path,
		    পরিমাণ(sunaddr.sun_path)) >= পরিমাণ(sunaddr.sun_path)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    path);
			ভঙ্গ;
		}

		যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ভঙ্গ;
		}
		যদি (bind(sock, (সংরচনা sockaddr *)&sunaddr,
		    পরিমাণ(sunaddr)) == -1) {
			যদি (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    path, strerror(errno));
				close(sock);
				sock = -1;
				অনুৱর্ত;
			}
			error_f("bind \"%s\": %.100s", path, strerror(errno));
			ভঙ্গ;
		}
		যদি (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", path, strerror(errno));
			ভঙ্গ;
		}
		good = 1;
	}
	umask(prev_mask);
	যদি (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    path, sock);
	} অন্যথা যদি (sock != -1) {
		close(sock);
		sock = -1;
	}
	ঘূৰাই sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
স্থির পূর্ণাঙ্ক
agent_listener_shared(ধ্রুৱ ৱর্ণ *parent_dir, pid_t pid, ধ্রুৱ ৱর্ণ *tag,
    পূর্ণাঙ্ক *sockp, ৱর্ণ **pathp, ৱর্ণ **dirp)
{
	ৱর্ণ *dir = রিক্ত, *path = রিক্ত;
	পূর্ণাঙ্ক sock, ret = -1;
	mode_t prev_mask;

	*pathp = *dirp = রিক্ত;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", parent_dir);
	যদি (mkdtemp(dir) == রিক্ত) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		গচ্ছ out;
	}
	xasprintf(&path, "%s/agent.%s.%ld", dir, tag, (long)pid);
	prev_mask = umask(0177);
	যদি ((sock = unix_listener(path, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_mask);
		যদি (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		গচ্ছ out;
	}
	umask(prev_mask);

	/* Success */
	*dirp = dir;
	dir = রিক্ত; /* transferred */
	*pathp = path;
	path = রিক্ত; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	মুক্ত(dir);
	মুক্ত(path);
	ঘূৰাই ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
স্থির পূর্ণাঙ্ক
agent_listener_user(ধ্রুৱ ৱর্ণ *dir, pid_t pid, ধ্রুৱ ৱর্ণ *tag,
    পূর্ণাঙ্ক *sockp, ৱর্ণ **pathp)
{
	ৱর্ণ *hostnamehash = রিক্ত, *path = রিক্ত;
	পূর্ণাঙ্ক sock, ret = -1;

	যদি ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == রিক্ত)
		ঘূৰাই -1;
	xasprintf(&path, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, tag, (long long)pid);
	যদি (mkdir_path(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		গচ্ছ out;
	}
	যদি ((sock = unix_listener_tmp(path, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		গচ্ছ out;
	}
	/* Success */
	*pathp = path;
	path = রিক্ত; /* transferred */
	*sockp = sock;
	ret = 0;
 out:
	মুক্ত(hostnamehash);
	মুক্ত(path);
	ঘূৰাই ret;
}

স্থির ৱর্ণ *
expand_pathspec(ধ্রুৱ ৱর্ণ *path, ধ্রুৱ ৱর্ণ *username,
    uid_t uid, ধ্রুৱ ৱর্ণ *homedir)
{
	ৱর্ণ *uidbuf = রিক্ত, *dir = রিক্ত, *tmp = রিক্ত;

	xasprintf(&uidbuf, "%lld", (long long)uid);

	যদি ((tmp = percent_expand(path, "u", username, "U", uidbuf,
	    "h", homedir, রিক্ত)) == রিক্ত) {
		error_f("failed to percent-expand agent socket directory");
		গচ্ছ out;
	}
	যদি (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		গচ্ছ out;
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
	ঘূৰাই dir;
}

পূর্ণাঙ্ক
agent_listener(ধ্রুৱ ৱর্ণ *pathspec, ধ্রুৱ ৱর্ণ *username, uid_t uid,
    ধ্রুৱ ৱর্ণ *homedir, pid_t pid, ধ্রুৱ ৱর্ণ *tag, পূর্ণাঙ্ক *sockp,
    ৱর্ণ **pathp, ৱর্ণ **dirp)
{
	পূর্ণাঙ্ক sock = -1, ret = -1;
	ৱর্ণ *path = রিক্ত, *dir = রিক্ত;

	*sockp = -1;
	*pathp = *dirp = রিক্ত;

	যদি (pathspec == রিক্ত || pathspec[0] == '\0') {
		error_f("no agent path specified");
		ঘূৰাই -1;
	}
	যদি (strncmp(pathspec, "shared:", 7) == 0) {
		যদি (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			গচ্ছ out;
		}
		যদি ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == রিক্ত) {
			/* Error already logged */
			গচ্ছ out;
		}
		যদি (agent_listener_shared(dir, pid, tag,
		    &sock, &path, dirp) != 0) {
			/* Error already logged */
			গচ্ছ out;
		}
	} অন্যথা যদি (strncmp(pathspec, "user:", 5) == 0) {
		যদি ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == রিক্ত) {
			/* Error already logged */
			গচ্ছ out;
		}
		যদি (agent_listener_user(dir, pid, tag, &sock, &path) != 0) {
			/* Error already logged */
			গচ্ছ out;
		}
	} অন্যথা {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		গচ্ছ out;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = path;
	path = রিক্ত; /* transferred */
 out:
	মুক্ত(path);
	মুক্ত(dir);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
agent_listener_cleanup(ধ্রুৱ ৱর্ণ *pathspec, ধ্রুৱ ৱর্ণ *sockpath,
    ধ্রুৱ ৱর্ণ *sockdir)
{
	যদি (sockpath == রিক্ত)
		ঘূৰাই 0;
	যদি (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		ঘূৰাই -1;
	}
	debug3_f("removed socket %s", sockpath);

	যদি (pathspec == রিক্ত)
		ঘূৰাই 0;
	যদি (strncmp(pathspec, "shared:", 7) == 0 && sockdir != রিক্ত) {
		যদি (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			ঘূৰাই -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
socket_is_stale(ধ্রুৱ ৱর্ণ *path)
{
	পূর্ণাঙ্ক fd, r;
	সংরচনা sockaddr_un sunaddr;
	socklen_t l = পরিমাণ(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', পরিমাণ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	যদি (strlcpy(sunaddr.sun_path, path,
	    পরিমাণ(sunaddr.sun_path)) >= পরিমাণ(sunaddr.sun_path)) {
		debug_f("path for \"%s\" too long for sockaddr_un", path);
		ঘূৰাই 0;
	}
	যদি ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		ঘূৰাই 0;
	}
	set_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	যদি (connect(fd, (সংরচনা sockaddr *)&sunaddr, পরিমাণ(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", path, strerror(errno));
		close(fd);
		ঘূৰাই 1;
	}
	যদি (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		ঘূৰাই 0;
	}
	যদি (r != 0) {
		debug_f("socket error on %s: %s", path, strerror(errno));
		close(fd);
		ঘূৰাই 1;
	}
	close(fd);
	debug_f("socket %s seems still active", path);
	ঘূৰাই 0;
}

#ifndef HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(path, buf)
#endif
#ifndef HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(path)
#endif

শূন্য
agent_cleanup_stale(ধ্রুৱ ৱর্ণ *pathspec, ধ্রুৱ ৱর্ণ *username, uid_t uid,
    ধ্রুৱ ৱর্ণ *homedir, পূর্ণাঙ্ক ignore_hosthash)
{
	DIR *d = রিক্ত;
	সংরচনা dirent *dp;
	সংরচনা stat sb;
	ৱর্ণ *prefix = রিক্ত, *dir = রিক্ত, *path;
	সংরচনা timespec now, sub, *mtimp = রিক্ত;

	/* Only clean up user socket directories */
	যদি (pathspec == রিক্ত || strncmp(pathspec, "user:", 5) != 0)
		ঘূৰাই;

	যদি ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == রিক্ত)
		ঘূৰাই; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	যদি (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		গচ্ছ out;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	যদি (!ignore_hosthash) {
		যদি ((path = agent_hostname_hash()) == রিক্ত) {
			error_f("couldn't get hostname hash");
			গচ্ছ out;
		}
		xasprintf(&prefix, "s.%s.", path);
		মুক্ত(path);
	}

	যদি ((d = opendir(dir)) == রিক্ত) {
		যদি (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		গচ্ছ out;
	}
	যেতিয়ালৈ ((dp = readdir(d)) != রিক্ত) {
#ifdef HAVE_DIRENT_D_TYPE
		যদি (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			অনুৱর্ত;
#endif
		যদি (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			অনুৱর্ত;
		}
		যদি (!S_ISSOCK(sb.st_mode))
			অনুৱর্ত;
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
			অনুৱর্ত;
		}
		যদি (!ignore_hosthash &&
		    strncmp(dp->d_name, prefix, strlen(prefix)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			অনুৱর্ত;
		}
		xasprintf(&path, "%s/%s", dir, dp->d_name);
		যদি (socket_is_stale(path)) {
			debug_f("cleanup stale socket %s", path);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		মুক্ত(path);
	}
 out:
	যদি (d != রিক্ত)
		closedir(d);
	মুক্ত(dir);
	মুক্ত(prefix);
}

#undef unlinkat
#undef fstatat
