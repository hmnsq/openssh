#include "fixed-keys.h"
#include <assert.h>

#define メインページ(ac, av) xxxmain(ac, av)
#include "../../../ssh-agent.c"

void test_one(const uint8_t* s, size_t slen);

static 整数
devnull_or_die(void)
{
	整数 fd;

	もし ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	戻る fd;
}

static struct sshkey *
pubkey_or_die(const char *s)
{
	char *tmp, *cp;
	struct sshkey *pubkey;
	整数 r;

	tmp = cp = xstrdup(s);
	もし ((pubkey = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	もし ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	free(tmp);
	戻る pubkey;
}

static struct sshkey *
privkey_or_die(const char *s)
{
	整数 r;
	struct sshbuf *b;
	struct sshkey *privkey;

	もし ((b = sshbuf_from(s, strlen(s))) == NULL) {
		error_f("sshbuf_from failed");
		abort();
	}
	もし ((r = sshkey_parse_private_fileblob(b, "", &privkey, NULL)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	戻る privkey;
}

static void
add_key(const char *privkey, const char *certpath)
{
	Identity *id;
	整数 r;
	struct sshkey *cert;

	id = xcalloc(1, sizeof(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->key = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	もし (sshkey_is_sk(id->key))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, sizeof(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->key = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	もし ((r = sshkey_to_certified(id->key)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	もし ((r = sshkey_cert_copy(cert, id->key)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	もし (sshkey_is_sk(id->key))
		id->sk_provider = xstrdup("internal");
}

static void
cleanup_idtab(void)
{
	Identity *id;

	もし (idtab == NULL) 戻る;
	ために (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}
	free(idtab);
	idtab = NULL;
}

static void
reset_idtab(void)
{
	cleanup_idtab();
	idtab_init();
	// Load keys.
	add_key(PRIV_RSA, CERT_RSA);
	add_key(PRIV_ECDSA, CERT_ECDSA);
	add_key(PRIV_ED25519, CERT_ED25519);
	add_key(PRIV_ECDSA_SK, CERT_ECDSA_SK);
	add_key(PRIV_ED25519_SK, CERT_ED25519_SK);
}

static void
cleanup_sockettab(void)
{
	u_int i;
	ために (i = 0; i < sockets_alloc; i++) {
		もし (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	free(sockets);
	sockets = NULL;
	sockets_alloc = 0;
}

static void
reset_sockettab(整数 devnull)
{
	整数 fd;

	cleanup_sockettab();
	もし ((fd = dup(devnull)) == -1) {
		error_f("dup: %s", strerror(errno));
		abort();
	}
	new_socket(AUTH_CONNECTION, fd);
	assert(sockets[0].type == AUTH_CONNECTION);
	assert(sockets[0].fd == fd);
}

#define MAX_MESSAGES 256
void
test_one(const uint8_t* s, size_t slen)
{
	static 整数 devnull = -1;
	size_t i, olen, nlen;

	もし (devnull == -1) {
		log_init(__progname, SYSLOG_LEVEL_DEBUG3,
		    SYSLOG_FACILITY_AUTH, 1);
		devnull = devnull_or_die();
		allowed_providers = xstrdup("");
		websafe_allowlist = xstrdup("*");
		setenv("DISPLAY", "", 1); /* ban askpass */
	}

	reset_idtab();
	reset_sockettab(devnull);
	(void)sshbuf_put(sockets[0].input, s, slen);
	ために (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].input);
		process_message(0);
		nlen = sshbuf_len(sockets[0].input);
		もし (nlen == 0 || nlen == olen)
			break;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
