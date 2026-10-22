/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "xmalloc.h"

संरचना sshbuf *cfg;

/* stub */
पूर्णाङ्क auth2_methods_valid(ध्रुव वर्ण *methods, पूर्णाङ्क need_enable);
पूर्णाङ्क
auth2_methods_valid(ध्रुव वर्ण *methods, पूर्णाङ्क need_enable)
{
	प्रत्यागम 1;
}

स्थिर शून्य
onerror(शून्य *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((संरचना fuzz *)fuzz);
}

स्थिर शून्य
set_string(वर्ण **dst, ध्रुव वर्ण *s)
{
	*dst = s == रिक्त ? रिक्त : xstrdup(s);
}

स्थिर वर्ण **
new_string_array(u_int n)
{
	प्रत्यागम xcalloc(n, परिमाण(वर्ण *));
}

स्थिर शून्य
set_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->अंक_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_mask = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	set_string(&o->permit_user_env_allowlist, "");
	o->rekey_limit = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	set_string(&o->routing_domain, "");
	set_string(&o->banner, रिक्त);
	set_string(&o->adm_forced_command, "internal-sftp");
	set_string(&o->chroot_directory, "");
	set_string(&o->host_कुंजी_agent, रिक्त);
	set_string(&o->authorized_कुंजियाँ_command, "/bin/echo");
	set_string(&o->authorized_कुंजियाँ_command_user, "");
	set_string(&o->authorized_principals_file, रिक्त);

	o->अंक_authkeys_files = 3;
	o->authorized_कुंजियाँ_files = new_string_array(o->अंक_authkeys_files);
	set_string(&o->authorized_कुंजियाँ_files[0], रिक्त);
	set_string(&o->authorized_कुंजियाँ_files[1], "");
	set_string(&o->authorized_कुंजियाँ_files[2], ".ssh/authorized_keys");

	o->अंक_log_verbose = 2;
	o->log_verbose = new_string_array(o->अंक_log_verbose);
	set_string(&o->log_verbose[0], रिक्त);
	set_string(&o->log_verbose[1], "kex.c:*");

	o->अंक_host_कुंजी_files = 3;
	o->host_कुंजी_file_userprovided =
	    xcalloc(o->अंक_host_कुंजी_files,
	    परिमाण(*o->host_कुंजी_file_userprovided));
	o->host_कुंजी_files = new_string_array(o->अंक_host_कुंजी_files);
	o->host_कुंजी_file_userprovided[0] = 0;
	o->host_कुंजी_file_userprovided[1] = 1;
	o->host_कुंजी_file_userprovided[2] = -1;
	set_string(&o->host_कुंजी_files[0], रिक्त);
	set_string(&o->host_कुंजी_files[1], "");
	set_string(&o->host_कुंजी_files[2], "/tmp/ssh_host_ed25519_key");

	o->अंक_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->अंक_queued_listens,
	    परिमाण(*o->queued_listen_addrs));
	set_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].port = 2222;
	set_string(&o->queued_listen_addrs[0].rdomain, रिक्त);
	set_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].port = -1;
	set_string(&o->queued_listen_addrs[1].rdomain, "");

	o->अंक_subsystems = 2;
	o->subsystem_name = new_string_array(o->अंक_subsystems);
	o->subsystem_command = new_string_array(o->अंक_subsystems);
	o->subsystem_args = new_string_array(o->अंक_subsystems);
	set_string(&o->subsystem_name[0], "sftp");
	set_string(&o->subsystem_command[0], "internal-sftp");
	set_string(&o->subsystem_args[0], "internal-sftp -f AUTH");
	set_string(&o->subsystem_name[1], "echo");
	set_string(&o->subsystem_command[1], "/bin/echo");
	set_string(&o->subsystem_args[1], "/bin/echo hello");
}

स्थिर शून्य
check_roundtrip(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(out.अंक_ports, 2);
	ASSERT_INT_EQ(out.ports[0], 22);
	ASSERT_INT_EQ(out.ports[1], 2022);
	ASSERT_INT_EQ(out.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(out.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(out.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(out.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(out.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_mask, 0177);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(out.permit_user_env, 1);
	ASSERT_STRING_EQ(out.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(out.rekey_limit, 123456789);
	ASSERT_INT_EQ(out.rekey_interval, 600);
	ASSERT_U64_EQ(out.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(out.routing_domain, "");
	ASSERT_PTR_EQ(out.banner, रिक्त);
	ASSERT_STRING_EQ(out.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(out.chroot_directory, "");
	ASSERT_PTR_EQ(out.host_कुंजी_agent, रिक्त);
	ASSERT_STRING_EQ(out.authorized_कुंजियाँ_command, "/bin/echo");
	ASSERT_STRING_EQ(out.authorized_कुंजियाँ_command_user, "");
	ASSERT_PTR_EQ(out.authorized_principals_file, रिक्त);

	ASSERT_U_INT_EQ(out.अंक_authkeys_files, 3);
	ASSERT_PTR_EQ(out.authorized_कुंजियाँ_files[0], रिक्त);
	ASSERT_STRING_EQ(out.authorized_कुंजियाँ_files[1], "");
	ASSERT_STRING_EQ(out.authorized_कुंजियाँ_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(out.अंक_log_verbose, 2);
	ASSERT_PTR_EQ(out.log_verbose[0], रिक्त);
	ASSERT_STRING_EQ(out.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(out.अंक_host_कुंजी_files, 3);
	ASSERT_INT_EQ(out.host_कुंजी_file_userprovided[0], 0);
	ASSERT_INT_EQ(out.host_कुंजी_file_userprovided[1], 1);
	ASSERT_INT_EQ(out.host_कुंजी_file_userprovided[2], -1);
	ASSERT_PTR_EQ(out.host_कुंजी_files[0], रिक्त);
	ASSERT_STRING_EQ(out.host_कुंजी_files[1], "");
	ASSERT_STRING_EQ(out.host_कुंजी_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(out.अंक_queued_listens, 2);
	ASSERT_STRING_EQ(out.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(out.queued_listen_addrs[0].port, 2222);
	ASSERT_PTR_EQ(out.queued_listen_addrs[0].rdomain, रिक्त);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(out.queued_listen_addrs[1].port, -1);
	ASSERT_STRING_EQ(out.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(out.अंक_subsystems, 2);
	ASSERT_STRING_EQ(out.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(out.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(out.subsystem_args[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(out.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(out.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(out.subsystem_args[1], "/bin/echo hello");

	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_trailing_data(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions out;
	पूर्णाङ्क r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_bad_version(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions out;
	पूर्णाङ्क r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), रिक्त);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_bad_port_गिनती(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions out;
	पूर्णाङ्क r;

	initialize_server_options(&out);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_SIZE_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), रिक्त);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &out);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
check_roundtrip_signed_limits(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions out, in;

	initialize_server_options(&out);
	in = *o;
	in.fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	in.ip_qos_bulk = INT_MIN;
	in.rekey_limit = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&in, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(deserialise_server_options(buf, &out), 0);
	ASSERT_INT_EQ(out.fwd_opts.streamlocal_bind_mask == (mode_t)-1, 1);
	ASSERT_INT_EQ(out.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(out.rekey_limit, INT64_MIN);
	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
attempt_deserialise_blob(ध्रुव u_char *p, size_t len)
{
	संरचना sshbuf *buf;
	ServerOptions out;

	initialize_server_options(&out);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), रिक्त);
	(शून्य)deserialise_server_options(buf, &out);
	free_server_options(&out);
	sshbuf_free(buf);
}

स्थिर शून्य
check_fuzz_deserialise(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	यदि (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	यदि (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	प्रति (; !fuzz_done(fuzz); fuzz_next(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(रिक्त, रिक्त);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

शून्य
tests(शून्य)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_START("server options round trip preserves nullable state");
	set_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject trailing data");
	set_test_options(&o);
	check_rejects_trailing_data(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject unsupported version");
	set_test_options(&o);
	check_rejects_bad_version(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options reject bad port count");
	set_test_options(&o);
	check_rejects_bad_port_गिनती(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options round trip signed limits");
	set_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_DONE();

	TEST_START("server options deserialise fuzz");
	set_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_DONE();
}

शून्य
benchmarks(शून्य)
{
	printf("no benchmarks\n");
}
