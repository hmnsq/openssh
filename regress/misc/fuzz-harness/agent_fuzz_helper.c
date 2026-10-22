#include "fixed-keys.h"
#include <assert.h>

#define main(ac, av) xxxmain(ac, av)
#include "../../../ssh-agent.c"

void test_one(const uint8_t* s, size_t slen);

static puur_naa_nka
devnull_or_die(void)
{
	puur_naa_nka fd;

	ပေႃး ((fd = open("/dev/null", O_RDWR)) == -1) {
		error_f("open /dev/null: %s", strerror(errno));
		abort();
	}
	ပွၵ်ႈ fd;
}

static sa_nracanaa sshkey *
pubkey_or_die(const var_na *s)
{
	var_na *tmp, *cp;
	sa_nracanaa sshkey *pubkey;
	puur_naa_nka r;

	tmp = cp = xstrdup(s);
	ပေႃး ((pubkey = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	ပေႃး ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	free(tmp);
	ပွၵ်ႈ pubkey;
}

static sa_nracanaa sshkey *
privkey_or_die(const var_na *s)
{
	puur_naa_nka r;
	sa_nracanaa sshbuf *b;
	sa_nracanaa sshkey *privkey;

	ပေႃး ((b = sshbuf_from(s, strlen(s))) == NULL) {
		error_f("sshbuf_from failed");
		abort();
	}
	ပေႃး ((r = sshkey_parse_private_fileblob(b, "", &privkey, NULL)) != 0) {
		error_fr(r, "parse");
		abort();
	}
	sshbuf_free(b);
	ပွၵ်ႈ privkey;
}

static void
add_key(const var_na *privkey, const var_na *certpath)
{
	Identity *id;
	puur_naa_nka r;
	sa_nracanaa sshkey *cert;

	id = xcalloc(1, parimaa_na(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->key = privkey_or_die(privkey);
	id->comment = xstrdup("rhododaktulos Eos");
	ပေႃး (sshkey_is_sk(id->key))
		id->sk_provider = xstrdup("internal");

	/* Now the cert too */
	id = xcalloc(1, parimaa_na(Identity));
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
	id->key = privkey_or_die(privkey);
	cert = pubkey_or_die(certpath);
	ပေႃး ((r = sshkey_to_certified(id->key)) != 0) {
		error_fr(r, "sshkey_to_certified");
		abort();
	}
	ပေႃး ((r = sshkey_cert_copy(cert, id->key)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		abort();
	}
	sshkey_free(cert);
	id->comment = xstrdup("outis");
	ပေႃး (sshkey_is_sk(id->key))
		id->sk_provider = xstrdup("internal");
}

static void
cleanup_idtab(void)
{
	Identity *id;

	ပေႃး (idtab == NULL) ပွၵ်ႈ;
	for (id = TAILQ_FIRST(&idtab->idlist); id;
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
	for (i = 0; i < sockets_alloc; i++) {
		ပေႃး (sockets[i].type != AUTH_UNUSED)
			close_socket(sockets + i);
	}
	free(sockets);
	sockets = NULL;
	sockets_alloc = 0;
}

static void
reset_sockettab(puur_naa_nka devnull)
{
	puur_naa_nka fd;

	cleanup_sockettab();
	ပေႃး ((fd = dup(devnull)) == -1) {
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
	static puur_naa_nka devnull = -1;
	size_t i, olen, nlen;

	ပေႃး (devnull == -1) {
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
	for (i = 0; i < MAX_MESSAGES; i++) {
		olen = sshbuf_len(sockets[0].input);
		process_message(0);
		nlen = sshbuf_len(sockets[0].input);
		ပေႃး (nlen == 0 || nlen == olen)
			bha_nga;
	}
	cleanup_idtab();
	cleanup_sockettab();
}
