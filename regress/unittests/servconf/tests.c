/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ರಚನೆ sshbuf *cfg;

/* stub */
ಪೂರ್ಣಾಂಕ auth2_methods_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *methods, ಪೂರ್ಣಾಂಕ need_enable);
ಪೂರ್ಣಾಂಕ
auth2_methods_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *methods, ಪೂರ್ಣಾಂಕ need_enable)
{
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
onerror(ಶೂನ್ಯ *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((ರಚನೆ fuzz *)fuzz);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_string(ಅಕ್ಷರ **dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	*dst = s == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(s);
}

ಸ್ಥಿರ ಅಕ್ಷರ **
new_string_array(u_int n)
{
	ಹಿಂತಿರುಗಿ xcalloc(n, ಗಾತ್ರ(ಅಕ್ಷರ *));
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->ಅಂಕೆ_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	ಗಣ_string(&o->permit_user_env_allowlist, "");
	o->rekey_ಎಲ್ಲೆ = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	ಗಣ_string(&o->routing_domain, "");
	ಗಣ_string(&o->banner, ಖಾಲಿ);
	ಗಣ_string(&o->adm_forced_command, "internal-sftp");
	ಗಣ_string(&o->chroot_directory, "");
	ಗಣ_string(&o->host_ಕೀಲಿ_agent, ಖಾಲಿ);
	ಗಣ_string(&o->authorized_ಕೀಲಿಗಳು_command, "/bin/echo");
	ಗಣ_string(&o->authorized_ಕೀಲಿಗಳು_command_user, "");
	ಗಣ_string(&o->authorized_principals_file, ಖಾಲಿ);

	o->ಅಂಕೆ_authkeys_files = 3;
	o->authorized_ಕೀಲಿಗಳು_files = new_string_array(o->ಅಂಕೆ_authkeys_files);
	ಗಣ_string(&o->authorized_ಕೀಲಿಗಳು_files[0], ಖಾಲಿ);
	ಗಣ_string(&o->authorized_ಕೀಲಿಗಳು_files[1], "");
	ಗಣ_string(&o->authorized_ಕೀಲಿಗಳು_files[2], ".ssh/authorized_keys");

	o->ಅಂಕೆ_log_verbose = 2;
	o->log_verbose = new_string_array(o->ಅಂಕೆ_log_verbose);
	ಗಣ_string(&o->log_verbose[0], ಖಾಲಿ);
	ಗಣ_string(&o->log_verbose[1], "kex.c:*");

	o->ಅಂಕೆ_host_ಕೀಲಿ_files = 3;
	o->host_ಕೀಲಿ_file_userprovided =
	    xcalloc(o->ಅಂಕೆ_host_ಕೀಲಿ_files,
	    ಗಾತ್ರ(*o->host_ಕೀಲಿ_file_userprovided));
	o->host_ಕೀಲಿ_files = new_string_array(o->ಅಂಕೆ_host_ಕೀಲಿ_files);
	o->host_ಕೀಲಿ_file_userprovided[0] = 0;
	o->host_ಕೀಲಿ_file_userprovided[1] = 1;
	o->host_ಕೀಲಿ_file_userprovided[2] = -1;
	ಗಣ_string(&o->host_ಕೀಲಿ_files[0], ಖಾಲಿ);
	ಗಣ_string(&o->host_ಕೀಲಿ_files[1], "");
	ಗಣ_string(&o->host_ಕೀಲಿ_files[2], "/tmp/ssh_host_ed25519_key");

	o->ಅಂಕೆ_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->ಅಂಕೆ_queued_listens,
	    ಗಾತ್ರ(*o->queued_listen_addrs));
	ಗಣ_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].ಪೋರ್ಟ್ = 2222;
	ಗಣ_string(&o->queued_listen_addrs[0].rdomain, ಖಾಲಿ);
	ಗಣ_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].ಪೋರ್ಟ್ = -1;
	ಗಣ_string(&o->queued_listen_addrs[1].rdomain, "");

	o->ಅಂಕೆ_subsystems = 2;
	o->subsystem_name = new_string_array(o->ಅಂಕೆ_subsystems);
	o->subsystem_command = new_string_array(o->ಅಂಕೆ_subsystems);
	o->subsystem_ವಾದಗಳು = new_string_array(o->ಅಂಕೆ_subsystems);
	ಗಣ_string(&o->subsystem_name[0], "sftp");
	ಗಣ_string(&o->subsystem_command[0], "internal-sftp");
	ಗಣ_string(&o->subsystem_ವಾದಗಳು[0], "internal-sftp -f AUTH");
	ಗಣ_string(&o->subsystem_name[1], "echo");
	ಗಣ_string(&o->subsystem_command[1], "/bin/echo");
	ಗಣ_string(&o->subsystem_ವಾದಗಳು[1], "/bin/echo hello");
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_roundtrip(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ServerOptions ಹೊರಹೋಗು;

	initialize_server_options(&ಹೊರಹೋಗು);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ಹೊರಹೋಗು), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_ports, 2);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.ports[0], 22);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.ports[1], 2022);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.fwd_opts.streamlocal_bind_ಮುಖವಾಡ, 0177);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.permit_user_env, 1);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(ಹೊರಹೋಗು.rekey_ಎಲ್ಲೆ, 123456789);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.rekey_interval, 600);
	ASSERT_U64_EQ(ಹೊರಹೋಗು.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(ಹೊರಹೋಗು.routing_domain, "");
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.banner, ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.chroot_directory, "");
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_agent, ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.authorized_ಕೀಲಿಗಳು_command, "/bin/echo");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.authorized_ಕೀಲಿಗಳು_command_user, "");
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.authorized_principals_file, ಖಾಲಿ);

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_authkeys_files, 3);
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.authorized_ಕೀಲಿಗಳು_files[0], ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.authorized_ಕೀಲಿಗಳು_files[1], "");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.authorized_ಕೀಲಿಗಳು_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_log_verbose, 2);
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.log_verbose[0], ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_host_ಕೀಲಿ_files, 3);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_file_userprovided[0], 0);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_file_userprovided[1], 1);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_file_userprovided[2], -1);
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_files[0], ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_files[1], "");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.host_ಕೀಲಿ_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_queued_listens, 2);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(ಹೊರಹೋಗು.queued_listen_addrs[0].ಪೋರ್ಟ್, 2222);
	ASSERT_PTR_EQ(ಹೊರಹೋಗು.queued_listen_addrs[0].rdomain, ಖಾಲಿ);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(ಹೊರಹೋಗು.queued_listen_addrs[1].ಪೋರ್ಟ್, -1);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(ಹೊರಹೋಗು.ಅಂಕೆ_subsystems, 2);
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_ವಾದಗಳು[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(ಹೊರಹೋಗು.subsystem_ವಾದಗಳು[1], "/bin/echo hello");

	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_rejects_trailing_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ServerOptions ಹೊರಹೋಗು;
	ಪೂರ್ಣಾಂಕ r;

	initialize_server_options(&ಹೊರಹೋಗು);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &ಹೊರಹೋಗು);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_rejects_bad_ಆವೃತ್ತಿ(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ServerOptions ಹೊರಹೋಗು;
	ಪೂರ್ಣಾಂಕ r;

	initialize_server_options(&ಹೊರಹೋಗು);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ಖಾಲಿ);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &ಹೊರಹೋಗು);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_rejects_bad_ಪೋರ್ಟ್_ಎಣಿಕೆ(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ServerOptions ಹೊರಹೋಗು;
	ಪೂರ್ಣಾಂಕ r;

	initialize_server_options(&ಹೊರಹೋಗು);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ಖಾಲಿ);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &ಹೊರಹೋಗು);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_roundtrip_signed_limits(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ServerOptions ಹೊರಹೋಗು, ಒಳ;

	initialize_server_options(&ಹೊರಹೋಗು);
	ಒಳ = *o;
	ಒಳ.fwd_opts.streamlocal_bind_ಮುಖವಾಡ = (ಬಹುಲಕ_t)-1;
	ಒಳ.ip_qos_bulk = INT_MIN;
	ಒಳ.rekey_ಎಲ್ಲೆ = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&ಒಳ, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &ಹೊರಹೋಗು), 0);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.fwd_opts.streamlocal_bind_ಮುಖವಾಡ == (ಬಹುಲಕ_t)-1, 1);
	ASSERT_INT_EQ(ಹೊರಹೋಗು.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(ಹೊರಹೋಗು.rekey_ಎಲ್ಲೆ, INT64_MIN);
	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
attempt_deserialise_blob(ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len)
{
	ರಚನೆ sshbuf *buf;
	ServerOptions ಹೊರಹೋಗು;

	initialize_server_options(&ಹೊರಹೋಗು);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), ಖಾಲಿ);
	(ಶೂನ್ಯ)deserialise_server_options(buf, &ಹೊರಹೋಗು);
	free_server_options(&ಹೊರಹೋಗು);
	sshbuf_free(buf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_fuzz_deserialise(ಸ್ಥಿರಾಂಕ ServerOptions *o)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ರಚನೆ fuzz *fuzz;
	u_int fuzzers = FUZZ_1_ಬಿಟ್_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ಆರಂಭ | FUZZ_TRUNCATE_ಕೊನೆ;

	ಆದರೆ (test_is_fast())
		fuzzers &= ~FUZZ_1_ಬಿಟ್_FLIP;
	ಆದರೆ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ಖಾಲಿ);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	ಗಾಗಿ (; !fuzz_ಮುಗಿದ(fuzz); fuzz_ಮುಂದಿನ(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(ಖಾಲಿ, ಖಾಲಿ);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_ಆರಂಭ("server options round trip preserves nullable state");
	ಗಣ_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("server options reject trailing data");
	ಗಣ_test_options(&o);
	check_rejects_trailing_ದತ್ತಾಂಶ(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("server options reject unsupported version");
	ಗಣ_test_options(&o);
	check_rejects_bad_ಆವೃತ್ತಿ(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("server options reject bad port count");
	ಗಣ_test_options(&o);
	check_rejects_bad_ಪೋರ್ಟ್_ಎಣಿಕೆ(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("server options round trip signed limits");
	ಗಣ_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("server options deserialise fuzz");
	ಗಣ_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_ಮುಗಿದ();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
