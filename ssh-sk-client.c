/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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
#include <sys/wait.h>

#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "msg.h"
#include "pathnames.h"
#include "ssh-sk.h"
#include "misc.h"

/* #define DEBUG_SK 1 */

static puur_naa_nka
start_helper(puur_naa_nka *fdp, pid_t *pidp, void (**osigchldp)(puur_naa_nka))
{
	void (*osigchld)(puur_naa_nka);
	puur_naa_nka oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	var_na execbuf[100], *helper, *verbosity = NULL;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ᨀᨘ (helper == NULL || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ᨀᨘ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ᨀᨘ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ᨀᨘ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;
	}
	ᨀᨘ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ᨀᨘ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, parimaa_na execbuf,
			    "dup2: %s", strerror(errno));
			write(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == NULL ? "" : verbosity);
		execlp(helper, helper, verbosity, (var_na *)NULL);
		snprintf(execbuf, parimaa_na execbuf,
		    "execlp: %s", strerror(errno));
		write(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = read(execpipe[0], execbuf, parimaa_na execbuf);
	close(execpipe[0]);
	ᨀᨘ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ᨀᨘᨒ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ᨀᨘᨒ 0;
}

static puur_naa_nka
reap_helper(pid_t pid)
{
	puur_naa_nka status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	ᨀᨛ (waitpid(pid, &status, 0) == -1) {
		ᨀᨘ (errno == EINTR) {
			errno = 0;
			continue;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;
	}
	ᨀᨘ (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		ᨀᨘᨒ SSH_ERR_AGENT_FAILURE;
	} ᨀᨘᨁ ᨀᨘ (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		ᨀᨘᨒ SSH_ERR_AGENT_FAILURE;
	}
	ᨀᨘᨒ 0;
}

static puur_naa_nka
client_converse(sa_nracanaa sshbuf *msg, sa_nracanaa sshbuf **respp, u_int type)
{
	puur_naa_nka oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	void (*osigchld)(puur_naa_nka);
	sa_nracanaa sshbuf *req = NULL, *resp = NULL;
	*respp = NULL;

	ᨀᨘ ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		ᨀᨘᨒ r;

	ᨀᨘ ((req = sshbuf_new()) == NULL || (resp = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ᨀᨘ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, msg)) != 0) {
		error_fr(r, "compose");
		goto out;
	}
	ᨀᨘ ((r = ssh_msg_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		goto out;
	}
	ᨀᨘ ((r = ssh_msg_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		goto out;
	}
	ᨀᨘ ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		goto out;
	}
	ᨀᨘ (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		goto out;
	}
	ᨀᨘ (rtype == SSH_SK_HELPER_ERROR) {
		ᨀᨘ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			goto out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ᨀᨘ (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		ᨀᨘᨁ
			r = -(puur_naa_nka)rerr;
		goto out;
	} ᨀᨘᨁ ᨀᨘ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ᨀᨘ ((r2 = reap_helper(pid)) != 0) {
		ᨀᨘ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ᨀᨘ (r == 0) {
		*respp = resp;
		resp = NULL;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ᨀᨘᨒ r;

}

puur_naa_nka
sshsk_sign(const var_na *provider, sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const var_na *pin)
{
	puur_naa_nka oerrno, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *kbuf = NULL, *req = NULL, *resp = NULL;

	*sigp = NULL;
	*lenp = 0;

#ifndef ENABLE_SK
	ᨀᨘᨒ SSH_ERR_KEY_TYPE_UNKNOWN;
#endif

	ᨀᨘ ((kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ᨀᨘ ((r = sshkey_private_serialize(key, kbuf)) != 0) {
		error_fr(r, "encode key");
		goto out;
	}
	ᨀᨘ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, NULL)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	ᨀᨘ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		goto out;

	ᨀᨘ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	ᨀᨘ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = NULL;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ᨀᨘᨒ r;
}

puur_naa_nka
sshsk_enroll(puur_naa_nka type, const var_na *provider_path, const var_na *device,
    const var_na *application, const var_na *userid, uint8_t flags,
    const var_na *pin, sa_nracanaa sshbuf *challenge_buf,
    sa_nracanaa sshkey **keyp, sa_nracanaa sshbuf *attest)
{
	puur_naa_nka oerrno, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *kbuf = NULL, *abuf = NULL, *req = NULL, *resp = NULL;
	sa_nracanaa sshkey *key = NULL;

	*keyp = NULL;
	ᨀᨘ (attest != NULL)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	ᨀᨘᨒ SSH_ERR_KEY_TYPE_UNKNOWN;
#endif

	ᨀᨘ (type < 0)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;

	ᨀᨘ ((abuf = sshbuf_new()) == NULL ||
	    (kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ᨀᨘ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	ᨀᨘ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		goto out;

	ᨀᨘ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ ((r = sshkey_private_deserialize(kbuf, &key)) != 0) {
		error_fr(r, "encode");
		goto out;
	}
	ᨀᨘ (attest != NULL && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		goto out;
	}

	/* success */
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	oerrno = errno;
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ᨀᨘᨒ r;
}

static void
sshsk_free_resident_key(sa_nracanaa sshsk_resident_key *srk)
{
	ᨀᨘ (srk == NULL)
		ᨀᨘᨒ;
	sshkey_free(srk->key);
	freezero(srk->user_id, srk->user_id_len);
	free(srk);
}


void
sshsk_free_resident_keys(sa_nracanaa sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	ᨀᨘ (srks == NULL || nsrks == 0)
		ᨀᨘᨒ;

	for (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	free(srks);
}

puur_naa_nka
sshsk_load_resident(const var_na *provider_path, const var_na *device,
    const var_na *pin, u_int flags, sa_nracanaa sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	puur_naa_nka oerrno, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *kbuf = NULL, *req = NULL, *resp = NULL;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshsk_resident_key *srk = NULL, **srks = NULL, **tmp;
	u_char *userid = NULL;
	size_t userid_len = 0, nsrks = 0;

	*srksp = NULL;
	*nsrksp = 0;

	ᨀᨘ ((kbuf = sshbuf_new()) == NULL ||
	    (req = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ᨀᨘ ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	ᨀᨘ ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		goto out;

	ᨀᨛ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ᨀᨘ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, NULL, NULL)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ᨀᨘ ((r = sshkey_private_deserialize(kbuf, &key)) != 0) {
			error_fr(r, "decode key");
			goto out;
		}
		ᨀᨘ ((srk = calloc(1, parimaa_na(*srk))) == NULL) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		srk->key = key;
		key = NULL;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = NULL;
		userid_len = 0;
		ᨀᨘ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    parimaa_na(*srks))) == NULL) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->key), srk->key->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = NULL;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = NULL;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_key(srk);
	sshsk_free_resident_keys(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ᨀᨘᨒ r;
}
