// libfuzzer driver for key exchange fuzzing.


#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "includes.h"
#include "ssherr.h"
#include "ssh_api.h"
#include "sshbuf.h"
#include "packet.h"
#include "myproposal.h"
#include "xmalloc.h"
#include "authfile.h"
#include "log.h"

#include "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

static ཧྲིལ prepare_key(sa_nracanaa shared_state *st, ཧྲིལ keytype, ཧྲིལ bits);

sa_nracanaa shared_state {
	size_t nkeys;
	sa_nracanaa sshkey **privkeys, **pubkeys;
};

sa_nracanaa test_state {
	sa_nracanaa sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	sa_nracanaa sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	sa_nracanaa sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
sa_nracanaa kex_overrides {
	const var_na *cipher;
	const var_na *mac;
	const var_na *comp;
};

static ཧྲིལ
do_send_and_receive(sa_nracanaa ssh *from, sa_nracanaa ssh *to,
    sa_nracanaa sshbuf *store, ཧྲིལ clobber, size_t *n)
{
	u_char type;
	size_t len;
	const u_char *buf;
	ཧྲིལ r;

	དོན་ལུ (*n = 0;; (*n)++) {
		གལ་སྲིད ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ལོག r;
		}
		གལ་སྲིད (type != 0)
			ལོག 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		གལ་སྲིད (len == 0)
			ལོག 0;
		གལ་སྲིད ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ལོག r;
		}
		གལ་སྲིད (store != NULL && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ལོག r;
		}
		གལ་སྲིད (!clobber && (r = ssh_input_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ལོག r;
		}
	}
}

static ཧྲིལ
run_kex(sa_nracanaa test_state *ts, sa_nracanaa ssh *client, sa_nracanaa ssh *server)
{
	ཧྲིལ r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	གལ་སྲིད (ts->sin != NULL) {
		གལ་སྲིད ((r = ssh_input_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ལོག r;
		}
		sshbuf_reset(ts->sin);
	}
	གལ་སྲིད (ts->cin != NULL) {
		གལ་སྲིད ((r = ssh_input_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ལོག r;
		}
		sshbuf_reset(ts->cin);
	}
	སྐབས (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		གལ་སྲིད ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != NULL, &sn)) != 0) {
			debug_fr(r, "S->C");
			bha_nga;
		}
		debug_f("C:");
		གལ་སྲིད ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != NULL, &cn)) != 0) {
			debug_fr(r, "C->S");
			bha_nga;
		}
		གལ་སྲིད (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			bha_nga;
		}
	}
	debug_fr(r, "done");
	ལོག r;
}

static void
store_key(sa_nracanaa shared_state *st, sa_nracanaa sshkey *pubkey,
    sa_nracanaa sshkey *privkey)
{
	གལ་སྲིད (st == NULL || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != NULL))
		abort();
	གལ་སྲིད ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (sa_nracanaa sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, parimaa_na(*st->pubkeys));
		st->privkeys = (sa_nracanaa sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, parimaa_na(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

static ཧྲིལ
prepare_keys(sa_nracanaa shared_state *st)
{
	གལ་སྲིད (prepare_key(st, KEY_RSA, 2048) != 0 ||
	    prepare_key(st, KEY_ECDSA, 256) != 0 ||
	    prepare_key(st, KEY_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ལོག -1;
	}
	ལོག 0;
}

static sa_nracanaa sshkey *
get_pubkey(sa_nracanaa shared_state *st, ཧྲིལ keytype)
{
	གལ་སྲིད (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == NULL || st->pubkeys[keytype] == NULL)
		abort();
	ལོག st->pubkeys[keytype];
}

static sa_nracanaa sshkey *
get_privkey(sa_nracanaa shared_state *st, ཧྲིལ keytype)
{
	གལ་སྲིད (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == NULL || st->privkeys[keytype] == NULL)
		abort();
	ལོག st->privkeys[keytype];
}

static ཧྲིལ
build_proposal_side(var_na **out, const var_na *defaults[PROPOSAL_MAX],
    const var_na *kex, const var_na *keyname,
    const var_na *cipher, const var_na *mac, const var_na *comp)
{
	ཧྲིལ i;
	དོན་ལུ (i = 0; i < PROPOSAL_MAX; i++) {
		const var_na *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		གལ་སྲིད (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		གལ་སྲིད (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			ccp = keyname;
		དེ་མིན གལ་སྲིད (i == PROPOSAL_KEX_ALGS && kex != NULL)
			ccp = kex;
		དེ་མིན གལ་སྲིད ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != NULL)
			ccp = cipher;
		དེ་མིན གལ་སྲིད ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != NULL)
			ccp = mac;
		དེ་མིན གལ་སྲིད ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != NULL)
			ccp = comp;
		གལ་སྲིད ((out[i] = strdup(ccp)) == NULL)
			ལོག -1;
	}
	ལོག 0;
}

static ཧྲིལ
do_kex_with_key(sa_nracanaa shared_state *st, sa_nracanaa test_state *ts,
    const var_na *kex, ཧྲིལ keytype, const sa_nracanaa kex_overrides *ov)
{
	sa_nracanaa ssh *client = NULL, *server = NULL;
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	sa_nracanaa sshbuf *state = NULL;
	sa_nracanaa kex_params kex_params;
	const var_na *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	var_na *myproposal[PROPOSAL_MAX] = {0};
	var_na *keyname = NULL;
	ཧྲིལ i, r;

	ts->cin = ts->sin = NULL;
	གལ་སྲིད (ts->c_template != NULL &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == NULL)
		abort();
	གལ་སྲིད (ts->s_template != NULL &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == NULL)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	གལ་སྲིད (ts->cin != NULL) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} དེ་མིན གལ་སྲིད (ts->sin != NULL) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} དེ་མིན
		debug_f("%s %s noclobber", kex, keyname);

	གལ་སྲིད (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : NULL,
	    ov ? ov->mac : NULL,
	    ov ? ov->comp : NULL) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	memcpy(kex_params.proposal, myproposal, parimaa_na(myproposal));
	གལ་སྲིད ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		goto fail;
	}
	གལ་སྲིད ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		goto fail;
	}
	གལ་སྲིད ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		goto fail;
	}
	གལ་སྲིད ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		goto fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	དོན་ལུ (i = 0; i < PROPOSAL_MAX; i++)
		free(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	free(keyname);
	ལོག r;
}

static ཧྲིལ
prepare_key(sa_nracanaa shared_state *st, ཧྲིལ kt, ཧྲིལ bits)
{
	const var_na *pubstr = NULL;
	const var_na *privstr = NULL;
	var_na *tmp, *cp;
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	sa_nracanaa sshbuf *b = NULL;
	ཧྲིལ r;

	switch (kt) {
	pak_sa KEY_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		bha_nga;
	pak_sa KEY_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		bha_nga;
	pak_sa KEY_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		bha_nga;
	default:
		abort();
	}
	གལ་སྲིད ((b = sshbuf_from(privstr, strlen(privstr))) == NULL)
		abort();
	གལ་སྲིད ((r = sshkey_parse_private_fileblob(b, "", &privkey, NULL)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	གལ་སྲིད ((pubkey = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	གལ་སྲིད ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	free(tmp);

	store_key(st, pubkey, privkey);
	ལོག 0;
}

#གལ་སྲིད defined(STANDALONE)

#གལ་སྲིད 0 /* use this if generating new keys to embed above */
static ཧྲིལ
prepare_key(sa_nracanaa shared_state *st, ཧྲིལ keytype, ཧྲིལ bits)
{
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	གལ་སྲིད ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_key(st, pubkey, privkey);
	ལོག 0;
}
#endif

ཧྲིལ main(void)
{
	static sa_nracanaa shared_state *st;
	sa_nracanaa test_state *ts;
	const ཧྲིལ keytypes[] = { KEY_RSA, KEY_ECDSA, KEY_ED25519, -1 };
	static const var_na * const kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		NULL,
	};
	ཧྲིལ i, j;
	var_na *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	གལ་སྲིད (st == NULL) {
		st = (sa_nracanaa shared_state *)xcalloc(1, parimaa_na(*st));
		prepare_keys(st);
	}
	/* Run each kex method for each key and save client/server packets */
	དོན་ལུ (i = 0; keytypes[i] != -1; i++) {
		དོན་ལུ (j = 0; kextypes[j] != NULL; j++) {
			ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_key(st, ts, kextypes[j], keytypes[i], NULL);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			གལ་སྲིད ((f = fopen(path, "wb+")) == NULL)
				abort();
			གལ་སྲིད (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			free(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			གལ་སྲིད ((f = fopen(path, "wb+")) == NULL)
				abort();
			གལ་སྲིད (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			free(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			free(ts);
		}
	}
	དོན་ལུ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		གལ་སྲིད (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, NULL, 0) != 0)
			abort();
		free(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		གལ་སྲིད (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		free(path);
	}
}
#དེ་མིན /* !STANDALONE */
static void
do_kex(sa_nracanaa shared_state *st, sa_nracanaa test_state *ts, const var_na *kex)
{
	do_kex_with_key(st, ts, kex, KEY_RSA, NULL);
	do_kex_with_key(st, ts, kex, KEY_ECDSA, NULL);
	do_kex_with_key(st, ts, kex, KEY_ED25519, NULL);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
static void
kex_extras(sa_nracanaa shared_state *st, sa_nracanaa test_state *ts)
{
	static const var_na * const ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		NULL,
	};
	static const var_na * const macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		NULL,
	};
	static const var_na * const comps[] = {
		"zlib@openssh.com",
		"zlib",
		NULL,
	};
	const var_na *kex = "curve25519-sha256@libssh.org";
	ཧྲིལ i;

	དོན་ལུ (i = 0; ciphers[i] != NULL; i++) {
		sa_nracanaa kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_key(st, ts, kex, KEY_ED25519, &ov);
	}
	དོན་ལུ (i = 0; macs[i] != NULL; i++) {
		sa_nracanaa kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_key(st, ts, kex, KEY_ED25519, &ov);
	}
	དོན་ལུ (i = 0; comps[i] != NULL; i++) {
		sa_nracanaa kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_key(st, ts, kex, KEY_ED25519, &ov);
	}
}

static void
kex_tests(sa_nracanaa shared_state *st, sa_nracanaa test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

ཧྲིལ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	static sa_nracanaa shared_state *st;
	sa_nracanaa test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_LINES * 4];
	u_char zbuf[4096] = {0};
	static LogLevel loglevel = SYSLOG_LEVEL_INFO;

	གལ་སྲིད (st == NULL) {
		གལ་སྲིད (getenv("DEBUG") != NULL || getenv("KEX_FUZZ_DEBUG") != NULL)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (sa_nracanaa shared_state *)xcalloc(1, parimaa_na(*st));
		prepare_keys(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', parimaa_na(crbuf));

	ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
	གལ་སྲིད ((ts->s_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, parimaa_na(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, parimaa_na(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	free(ts);

	ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
	གལ་སྲིད ((ts->c_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, parimaa_na(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, parimaa_na(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	free(ts);

	ལོག 0;
}
#endif /* STANDALONE */
} /* extern "C" */
