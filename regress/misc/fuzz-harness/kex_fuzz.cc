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

static ຈຳນວນເຕັມ prepare_key(sa_nracanaa shared_state *st, ຈຳນວນເຕັມ keytype, ຈຳນວນເຕັມ bits);

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

static ຈຳນວນເຕັມ
do_send_and_receive(sa_nracanaa ssh *from, sa_nracanaa ssh *to,
    sa_nracanaa sshbuf *store, ຈຳນວນເຕັມ clobber, size_t *n)
{
	u_char type;
	size_t len;
	const u_char *buf;
	ຈຳນວນເຕັມ r;

	ສຳລັບ (*n = 0;; (*n)++) {
		ຖ້າ ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ສົ່ງຄືນ r;
		}
		ຖ້າ (type != 0)
			ສົ່ງຄືນ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ຖ້າ (len == 0)
			ສົ່ງຄືນ 0;
		ຖ້າ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ສົ່ງຄືນ r;
		}
		ຖ້າ (store != NULL && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ສົ່ງຄືນ r;
		}
		ຖ້າ (!clobber && (r = ssh_input_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ສົ່ງຄືນ r;
		}
	}
}

static ຈຳນວນເຕັມ
run_kex(sa_nracanaa test_state *ts, sa_nracanaa ssh *client, sa_nracanaa ssh *server)
{
	ຈຳນວນເຕັມ r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	ຖ້າ (ts->sin != NULL) {
		ຖ້າ ((r = ssh_input_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ສົ່ງຄືນ r;
		}
		sshbuf_reset(ts->sin);
	}
	ຖ້າ (ts->cin != NULL) {
		ຖ້າ ((r = ssh_input_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ສົ່ງຄືນ r;
		}
		sshbuf_reset(ts->cin);
	}
	ໃນຂະນະທີ່ (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		ຖ້າ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != NULL, &sn)) != 0) {
			debug_fr(r, "S->C");
			bha_nga;
		}
		debug_f("C:");
		ຖ້າ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != NULL, &cn)) != 0) {
			debug_fr(r, "C->S");
			bha_nga;
		}
		ຖ້າ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			bha_nga;
		}
	}
	debug_fr(r, "done");
	ສົ່ງຄືນ r;
}

static void
store_key(sa_nracanaa shared_state *st, sa_nracanaa sshkey *pubkey,
    sa_nracanaa sshkey *privkey)
{
	ຖ້າ (st == NULL || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != NULL))
		abort();
	ຖ້າ ((size_t)pubkey->type >= st->nkeys) {
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

static ຈຳນວນເຕັມ
prepare_keys(sa_nracanaa shared_state *st)
{
	ຖ້າ (prepare_key(st, KEY_RSA, 2048) != 0 ||
	    prepare_key(st, KEY_ECDSA, 256) != 0 ||
	    prepare_key(st, KEY_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ສົ່ງຄືນ -1;
	}
	ສົ່ງຄືນ 0;
}

static sa_nracanaa sshkey *
get_pubkey(sa_nracanaa shared_state *st, ຈຳນວນເຕັມ keytype)
{
	ຖ້າ (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == NULL || st->pubkeys[keytype] == NULL)
		abort();
	ສົ່ງຄືນ st->pubkeys[keytype];
}

static sa_nracanaa sshkey *
get_privkey(sa_nracanaa shared_state *st, ຈຳນວນເຕັມ keytype)
{
	ຖ້າ (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == NULL || st->privkeys[keytype] == NULL)
		abort();
	ສົ່ງຄືນ st->privkeys[keytype];
}

static ຈຳນວນເຕັມ
build_proposal_side(var_na **out, const var_na *defaults[PROPOSAL_MAX],
    const var_na *kex, const var_na *keyname,
    const var_na *cipher, const var_na *mac, const var_na *comp)
{
	ຈຳນວນເຕັມ i;
	ສຳລັບ (i = 0; i < PROPOSAL_MAX; i++) {
		const var_na *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		ຖ້າ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		ຖ້າ (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			ccp = keyname;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (i == PROPOSAL_KEX_ALGS && kex != NULL)
			ccp = kex;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != NULL)
			ccp = cipher;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != NULL)
			ccp = mac;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != NULL)
			ccp = comp;
		ຖ້າ ((out[i] = strdup(ccp)) == NULL)
			ສົ່ງຄືນ -1;
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
do_kex_with_key(sa_nracanaa shared_state *st, sa_nracanaa test_state *ts,
    const var_na *kex, ຈຳນວນເຕັມ keytype, const sa_nracanaa kex_overrides *ov)
{
	sa_nracanaa ssh *client = NULL, *server = NULL;
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	sa_nracanaa sshbuf *state = NULL;
	sa_nracanaa kex_params kex_params;
	const var_na *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	var_na *myproposal[PROPOSAL_MAX] = {0};
	var_na *keyname = NULL;
	ຈຳນວນເຕັມ i, r;

	ts->cin = ts->sin = NULL;
	ຖ້າ (ts->c_template != NULL &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == NULL)
		abort();
	ຖ້າ (ts->s_template != NULL &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == NULL)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ຖ້າ (ts->cin != NULL) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (ts->sin != NULL) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} ບໍ່ດັ່ງນັ້ນ
		debug_f("%s %s noclobber", kex, keyname);

	ຖ້າ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : NULL,
	    ov ? ov->mac : NULL,
	    ov ? ov->comp : NULL) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	memcpy(kex_params.proposal, myproposal, parimaa_na(myproposal));
	ຖ້າ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		goto fail;
	}
	ຖ້າ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		goto fail;
	}
	ຖ້າ ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		goto fail;
	}
	ຖ້າ ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		goto fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	ສຳລັບ (i = 0; i < PROPOSAL_MAX; i++)
		free(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	free(keyname);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
prepare_key(sa_nracanaa shared_state *st, ຈຳນວນເຕັມ kt, ຈຳນວນເຕັມ bits)
{
	const var_na *pubstr = NULL;
	const var_na *privstr = NULL;
	var_na *tmp, *cp;
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	sa_nracanaa sshbuf *b = NULL;
	ຈຳນວນເຕັມ r;

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
	ຖ້າ ((b = sshbuf_from(privstr, strlen(privstr))) == NULL)
		abort();
	ຖ້າ ((r = sshkey_parse_private_fileblob(b, "", &privkey, NULL)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ຖ້າ ((pubkey = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	ຖ້າ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	free(tmp);

	store_key(st, pubkey, privkey);
	ສົ່ງຄືນ 0;
}

#ຖ້າ defined(STANDALONE)

#ຖ້າ 0 /* use this if generating new keys to embed above */
static ຈຳນວນເຕັມ
prepare_key(sa_nracanaa shared_state *st, ຈຳນວນເຕັມ keytype, ຈຳນວນເຕັມ bits)
{
	sa_nracanaa sshkey *privkey = NULL, *pubkey = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ຖ້າ ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_key(st, pubkey, privkey);
	ສົ່ງຄືນ 0;
}
#endif

ຈຳນວນເຕັມ main(void)
{
	static sa_nracanaa shared_state *st;
	sa_nracanaa test_state *ts;
	const ຈຳນວນເຕັມ keytypes[] = { KEY_RSA, KEY_ECDSA, KEY_ED25519, -1 };
	static const var_na * const kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		NULL,
	};
	ຈຳນວນເຕັມ i, j;
	var_na *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ຖ້າ (st == NULL) {
		st = (sa_nracanaa shared_state *)xcalloc(1, parimaa_na(*st));
		prepare_keys(st);
	}
	/* Run each kex method for each key and save client/server packets */
	ສຳລັບ (i = 0; keytypes[i] != -1; i++) {
		ສຳລັບ (j = 0; kextypes[j] != NULL; j++) {
			ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_key(st, ts, kextypes[j], keytypes[i], NULL);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ຖ້າ ((f = fopen(path, "wb+")) == NULL)
				abort();
			ຖ້າ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			free(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ຖ້າ ((f = fopen(path, "wb+")) == NULL)
				abort();
			ຖ້າ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
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
	ສຳລັບ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		ຖ້າ (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, NULL, 0) != 0)
			abort();
		free(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		ຖ້າ (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		free(path);
	}
}
#ບໍ່ດັ່ງນັ້ນ /* !STANDALONE */
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
	ຈຳນວນເຕັມ i;

	ສຳລັບ (i = 0; ciphers[i] != NULL; i++) {
		sa_nracanaa kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_key(st, ts, kex, KEY_ED25519, &ov);
	}
	ສຳລັບ (i = 0; macs[i] != NULL; i++) {
		sa_nracanaa kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_key(st, ts, kex, KEY_ED25519, &ov);
	}
	ສຳລັບ (i = 0; comps[i] != NULL; i++) {
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

ຈຳນວນເຕັມ LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	static sa_nracanaa shared_state *st;
	sa_nracanaa test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_LINES * 4];
	u_char zbuf[4096] = {0};
	static LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ຖ້າ (st == NULL) {
		ຖ້າ (getenv("DEBUG") != NULL || getenv("KEX_FUZZ_DEBUG") != NULL)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (sa_nracanaa shared_state *)xcalloc(1, parimaa_na(*st));
		prepare_keys(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', parimaa_na(crbuf));

	ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
	ຖ້າ ((ts->s_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, parimaa_na(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, parimaa_na(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	free(ts);

	ts = (sa_nracanaa test_state *)xcalloc(1, parimaa_na(*ts));
	ຖ້າ ((ts->c_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, parimaa_na(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, parimaa_na(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	free(ts);

	ສົ່ງຄືນ 0;
}
#endif /* STANDALONE */
} /* extern "C" */
