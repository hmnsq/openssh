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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <dirent.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <libgen.h>

#అన్తర్భావ "digest.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "xmalloc.h"

/* stuff shared by agent listeners (ssh-agent and sshd agent forwarding) */

#నిర్వచించు SOCKET_HOSTNAME_HASHLEN 10 /* length of hostname hash in socket path */

/* used for presenting random strings in unix_listener_tmp and hostname_hash */
స్థిర స్థిరరాశి అక్షరం presentation_chars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* returns a text-encoded hash of the hostname of specified length (max 64) */
స్థిర అక్షరం *
hostname_hash(కొలత_t len)
{
	అక్షరం hostname[NI_MAXHOST], p[65];
	u_char hash[64];
	పూర్ణాంకం r;
	కొలత_t l, i;

	l = ssh_digest_బైట్లు(SSH_DIGEST_SHA512);
	ఒకవేళ (len > 64) {
		error_f("bad length %zu >= max %zd", len, l);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (gethostname(hostname, పరిమాణం(hostname)) == -1) {
		error_f("gethostname: %s", strerror(errno));
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA512,
	    hostname, అక్షరశ్రేణి_పొడవు(hostname), hash, పరిమాణం(hash))) != 0) {
		error_fr(r, "ssh_digest_memory");
		తిరిగి ఖాళీ;
	}
	memset(p, '\0', పరిమాణం(p));
	కొరకు (i = 0; i < l; i++)
		p[i] = presentation_chars[
		    hash[i] % (పరిమాణం(presentation_chars) - 1)];
	/* debug3_f("hostname \"%s\" => hash \"%s\"", hostname, p); */
	p[len] = '\0';
	తిరిగి xstrdup(p);
}

స్థిర అక్షరం *
agent_hostname_hash(శూన్య)
{
	తిరిగి hostname_hash(SOCKET_HOSTNAME_HASHLEN);
}

/*
 * Creates a unix listener at a mkstemp(3)-style path, e.g. "/dir/sock.XXXXXX"
 * Supplied path is modified to the actual one used.
 */
స్థిర పూర్ణాంకం
unix_listener_tmp(అక్షరం *మార్గం, పూర్ణాంకం backlog)
{
	నిర్మాణం sockaddr_un sunaddr;
	పూర్ణాంకం good, sock = -1;
	కొలత_t i, xstart;
	బహుళకం_t prev_ముసుగు;

	/* Find first 'X' template character back from end of string */
	xstart = అక్షరశ్రేణి_పొడవు(మార్గం);
	అయితే (xstart > 0 && మార్గం[xstart - 1] == 'X')
		xstart--;

	memset(&sunaddr, 0, పరిమాణం(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	prev_ముసుగు = umask(0177);
	కొరకు (good = 0; !good;) {
		sock = -1;
		/* Randomise path suffix */
		కొరకు (i = xstart; మార్గం[i] != '\0'; i++) {
			మార్గం[i] = presentation_chars[
			    arc4random_ఏకరీతి(పరిమాణం(presentation_chars)-1)];
		}
		debug_f("trying path \"%s\"", మార్గం);

		ఒకవేళ (strlcpy(sunaddr.sun_మార్గం, మార్గం,
		    పరిమాణం(sunaddr.sun_మార్గం)) >= పరిమాణం(sunaddr.sun_మార్గం)) {
			error_f("path \"%s\" too long for Unix domain socket",
			    మార్గం);
			ఆపు;
		}

		ఒకవేళ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			error_f("socket: %.100s", strerror(errno));
			ఆపు;
		}
		ఒకవేళ (bind(sock, (నిర్మాణం sockaddr *)&sunaddr,
		    పరిమాణం(sunaddr)) == -1) {
			ఒకవేళ (errno == EADDRINUSE) {
				error_f("bind \"%s\": %.100s",
				    మార్గం, strerror(errno));
				close(sock);
				sock = -1;
				కొనసాగు;
			}
			error_f("bind \"%s\": %.100s", మార్గం, strerror(errno));
			ఆపు;
		}
		ఒకవేళ (listen(sock, backlog) == -1) {
			error_f("listen \"%s\": %s", మార్గం, strerror(errno));
			ఆపు;
		}
		good = 1;
	}
	umask(prev_ముసుగు);
	ఒకవేళ (good) {
		debug3_f("listening on unix socket \"%s\" as fd=%d",
		    మార్గం, sock);
	} లేకపోతే ఒకవేళ (sock != -1) {
		close(sock);
		sock = -1;
	}
	తిరిగి sock;
}

/*
 * Shared directory case (e.g. /tmp): create a temporary directory
 * for the socket.
 */
స్థిర పూర్ణాంకం
agent_listener_shared(స్థిరరాశి అక్షరం *మాతృ_dir, pid_t pid, స్థిరరాశి అక్షరం *ట్యాగ్,
    పూర్ణాంకం *sockp, అక్షరం **pathp, అక్షరం **dirp)
{
	అక్షరం *dir = ఖాళీ, *మార్గం = ఖాళీ;
	పూర్ణాంకం sock, ret = -1;
	బహుళకం_t prev_ముసుగు;

	*pathp = *dirp = ఖాళీ;
	xasprintf(&dir, "%s/ssh-XXXXXXXXXXXX", మాతృ_dir);
	ఒకవేళ (mkdtemp(dir) == ఖాళీ) {
		error_f("failed to create temporary directory "
		    "in \"%s\": %s", dir, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	xasprintf(&మార్గం, "%s/agent.%s.%ld", dir, ట్యాగ్, (దీర్ఘ)pid);
	prev_ముసుగు = umask(0177);
	ఒకవేళ ((sock = unix_listener(మార్గం, SSH_LISTEN_BACKLOG, 0)) < 0) {
		/* Error already logged */
		umask(prev_ముసుగు);
		ఒకవేళ (rmdir(dir) != 0)
			error_f("rmdir \"%s\": %s", dir, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	umask(prev_ముసుగు);

	/* Success */
	*dirp = dir;
	dir = ఖాళీ; /* transferred */
	*pathp = మార్గం;
	మార్గం = ఖాళీ; /* transferred */
	*sockp = sock;
	ret = 0;
 బహిర్గతం:
	విడుదల(dir);
	విడుదల(మార్గం);
	తిరిగి ret;
}

/*
 * User-specific directory case (e.g. ~/.ssh/agent): ensure directory
 * exists, and use a temp socket name under it.
 */
స్థిర పూర్ణాంకం
agent_listener_user(స్థిరరాశి అక్షరం *dir, pid_t pid, స్థిరరాశి అక్షరం *ట్యాగ్,
    పూర్ణాంకం *sockp, అక్షరం **pathp)
{
	అక్షరం *hostnamehash = ఖాళీ, *మార్గం = ఖాళీ;
	పూర్ణాంకం sock, ret = -1;

	ఒకవేళ ((hostnamehash = hostname_hash(SOCKET_HOSTNAME_HASHLEN)) == ఖాళీ)
		తిరిగి -1;
	xasprintf(&మార్గం, "%s/s.%s.%s.%lld.XXXXXXXXXX",
	    dir, hostnamehash, ట్యాగ్, (దీర్ఘ దీర్ఘ)pid);
	ఒకవేళ (mkdir_మార్గం(dir, 0700) != 0) {
		error_f("failed to create agent socket parent directory");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((sock = unix_listener_tmp(మార్గం, SSH_LISTEN_BACKLOG)) == -1) {
		/* error already logged */
		వెళ్ళు బహిర్గతం;
	}
	/* Success */
	*pathp = మార్గం;
	మార్గం = ఖాళీ; /* transferred */
	*sockp = sock;
	ret = 0;
 బహిర్గతం:
	విడుదల(hostnamehash);
	విడుదల(మార్గం);
	తిరిగి ret;
}

స్థిర అక్షరం *
expand_pathspec(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *username,
    uid_t uid, స్థిరరాశి అక్షరం *homedir)
{
	అక్షరం *uidbuf = ఖాళీ, *dir = ఖాళీ, *tmp = ఖాళీ;

	xasprintf(&uidbuf, "%lld", (దీర్ఘ దీర్ఘ)uid);

	ఒకవేళ ((tmp = percent_expand(మార్గం, "u", username, "U", uidbuf,
	    "h", homedir, ఖాళీ)) == ఖాళీ) {
		error_f("failed to percent-expand agent socket directory");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (tilde_expand(tmp, uid, &dir) != 0) {
		error_f("failed to user-expand agent socket directory");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (dir[0] != '/') {
		/* Assume it's relative to the home directory */
		విడుదల(tmp);
		tmp = dir;
		xasprintf(&dir, "%s/%s", homedir, tmp);
	}
 బహిర్గతం:
	విడుదల(uidbuf);
	విడుదల(tmp);
	తిరిగి dir;
}

పూర్ణాంకం
agent_listener(స్థిరరాశి అక్షరం *pathspec, స్థిరరాశి అక్షరం *username, uid_t uid,
    స్థిరరాశి అక్షరం *homedir, pid_t pid, స్థిరరాశి అక్షరం *ట్యాగ్, పూర్ణాంకం *sockp,
    అక్షరం **pathp, అక్షరం **dirp)
{
	పూర్ణాంకం sock = -1, ret = -1;
	అక్షరం *మార్గం = ఖాళీ, *dir = ఖాళీ;

	*sockp = -1;
	*pathp = *dirp = ఖాళీ;

	ఒకవేళ (pathspec == ఖాళీ || pathspec[0] == '\0') {
		error_f("no agent path specified");
		తిరిగి -1;
	}
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(pathspec, "shared:", 7) == 0) {
		ఒకవేళ (pathspec[7] != '/') {
			error_f("shared agent socket paths must be absolute");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((dir = expand_pathspec(pathspec + 7,
		    username, uid, homedir)) == ఖాళీ) {
			/* Error already logged */
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (agent_listener_shared(dir, pid, ట్యాగ్,
		    &sock, &మార్గం, dirp) != 0) {
			/* Error already logged */
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(pathspec, "user:", 5) == 0) {
		ఒకవేళ ((dir = expand_pathspec(pathspec + 5,
		    username, uid, homedir)) == ఖాళీ) {
			/* Error already logged */
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (agent_listener_user(dir, pid, ట్యాగ్, &sock, &మార్గం) != 0) {
			/* Error already logged */
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే {
		/* Shouldn't happen */
		error_f("unsupported agent path specification %s", pathspec);
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	ret = 0;
	*sockp = sock;
	*pathp = మార్గం;
	మార్గం = ఖాళీ; /* transferred */
 బహిర్గతం:
	విడుదల(మార్గం);
	విడుదల(dir);
	తిరిగి ret;
}

పూర్ణాంకం
agent_listener_cleanup(స్థిరరాశి అక్షరం *pathspec, స్థిరరాశి అక్షరం *sockpath,
    స్థిరరాశి అక్షరం *sockdir)
{
	ఒకవేళ (sockpath == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (unlink(sockpath) != 0) {
		error_f("unlink \"%s\": %s", sockpath, strerror(errno));
		తిరిగి -1;
	}
	debug3_f("removed socket %s", sockpath);

	ఒకవేళ (pathspec == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(pathspec, "shared:", 7) == 0 && sockdir != ఖాళీ) {
		ఒకవేళ (rmdir(sockdir) != 0) {
			error_f("rmdir \"%s\": %s", sockdir, strerror(errno));
			తిరిగి -1;
		}
		debug3_f("removed socket directory %s", sockdir);
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
socket_is_stale(స్థిరరాశి అక్షరం *మార్గం)
{
	పూర్ణాంకం fd, r;
	నిర్మాణం sockaddr_un sunaddr;
	socklen_t l = పరిమాణం(r);

	/* attempt non-blocking connect on socket */
	memset(&sunaddr, '\0', పరిమాణం(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	ఒకవేళ (strlcpy(sunaddr.sun_మార్గం, మార్గం,
	    పరిమాణం(sunaddr.sun_మార్గం)) >= పరిమాణం(sunaddr.sun_మార్గం)) {
		debug_f("path for \"%s\" too long for sockaddr_un", మార్గం);
		తిరిగి 0;
	}
	ఒకవేళ ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		error_f("socket: %s", strerror(errno));
		తిరిగి 0;
	}
	సమితి_nonblock(fd);
	/* a socket without a listener should yield an error immediately */
	ఒకవేళ (connect(fd, (నిర్మాణం sockaddr *)&sunaddr, పరిమాణం(sunaddr)) == -1) {
		debug_f("connect \"%s\": %s", మార్గం, strerror(errno));
		close(fd);
		తిరిగి 1;
	}
	ఒకవేళ (getsockopt(fd, SOL_SOCKET, SO_ERROR, &r, &l) == -1) {
		debug_f("getsockopt: %s", strerror(errno));
		close(fd);
		తిరిగి 0;
	}
	ఒకవేళ (r != 0) {
		debug_f("socket error on %s: %s", మార్గం, strerror(errno));
		close(fd);
		తిరిగి 1;
	}
	close(fd);
	debug_f("socket %s seems still active", మార్గం);
	తిరిగి 0;
}

#నిర్వచితం_కాకపోతే HAVE_FSTATAT
# define fstatat(x, y, buf, z) lstat(మార్గం, buf)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_UNLINKAT
# define unlinkat(x, y, z) unlink(మార్గం)
#అయితే_ముగింపు

శూన్య
agent_cleanup_stale(స్థిరరాశి అక్షరం *pathspec, స్థిరరాశి అక్షరం *username, uid_t uid,
    స్థిరరాశి అక్షరం *homedir, పూర్ణాంకం ignore_hosthash)
{
	DIR *d = ఖాళీ;
	నిర్మాణం dirent *dp;
	నిర్మాణం stat sb;
	అక్షరం *ఉపసర్గ = ఖాళీ, *dir = ఖాళీ, *మార్గం;
	నిర్మాణం timespec now, sub, *mtimp = ఖాళీ;

	/* Only clean up user socket directories */
	ఒకవేళ (pathspec == ఖాళీ || అక్షరశ్రేణి_పోలిక(pathspec, "user:", 5) != 0)
		తిరిగి;

	ఒకవేళ ((dir = expand_pathspec(pathspec + 5,
	    username, uid, homedir)) == ఖాళీ)
		తిరిగి; /* error already logged */

	debug_f("cleanup %s", dir);

	/* Only consider sockets last modified > 1 hour ago */
	ఒకవేళ (clock_gettime(CLOCK_REALTIME, &now) != 0) {
		error_f("clock_gettime: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	sub.tv_sec = 60 * 60;
	sub.tv_nsec = 0;
	timespecsub(&now, &sub, &now);

	/* Only consider sockets from the same hostname */
	ఒకవేళ (!ignore_hosthash) {
		ఒకవేళ ((మార్గం = agent_hostname_hash()) == ఖాళీ) {
			error_f("couldn't get hostname hash");
			వెళ్ళు బహిర్గతం;
		}
		xasprintf(&ఉపసర్గ, "s.%s.", మార్గం);
		విడుదల(మార్గం);
	}

	ఒకవేళ ((d = opendir(dir)) == ఖాళీ) {
		ఒకవేళ (errno != ENOENT)
			error_f("opendir \"%s\": %s", dir, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	అయితే ((dp = readdir(d)) != ఖాళీ) {
#నిర్వచితమైతే HAVE_DIRENT_D_TYPE
		ఒకవేళ (dp->d_type != DT_SOCK && dp->d_type != DT_UNKNOWN)
			కొనసాగు;
#అయితే_ముగింపు
		ఒకవేళ (fstatat(dirfd(d), dp->d_name,
		    &sb, AT_SYMLINK_NOFOLLOW) != 0 && errno != ENOENT) {
			error_f("stat \"%s/%s\": %s",
			    dir, dp->d_name, strerror(errno));
			కొనసాగు;
		}
		ఒకవేళ (!S_ISSOCK(sb.st_mode))
			కొనసాగు;
#నిర్వచితమైతే HAVE_STRUCT_STAT_ST_MTIM
		mtimp = &sb.st_mtim;
#లేకపోతే
		sub.tv_sec = sb.st_mtime;
		sub.tv_nsec = 0;
		mtimp = &sub;
#అయితే_ముగింపు
		ఒకవేళ (timespeccmp(mtimp, &now, >)) {
			debug3_f("Ignoring recent socket \"%s/%s\"",
			    dir, dp->d_name);
			కొనసాగు;
		}
		ఒకవేళ (!ignore_hosthash &&
		    అక్షరశ్రేణి_పోలిక(dp->d_name, ఉపసర్గ, అక్షరశ్రేణి_పొడవు(ఉపసర్గ)) != 0) {
			debug3_f("Ignoring socket \"%s/%s\" "
			    "from different host", dir, dp->d_name);
			కొనసాగు;
		}
		xasprintf(&మార్గం, "%s/%s", dir, dp->d_name);
		ఒకవేళ (socket_is_stale(మార్గం)) {
			debug_f("cleanup stale socket %s", మార్గం);
			unlinkat(dirfd(d), dp->d_name, 0);
		}
		విడుదల(మార్గం);
	}
 బహిర్గతం:
	ఒకవేళ (d != ఖాళీ)
		closedir(d);
	విడుదల(dir);
	విడుదల(ఉపసర్గ);
}

#నిర్వచనం_రద్దు unlinkat
#నిర్వచనం_రద్దు fstatat
