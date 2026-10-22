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
समुच्चयः_string(वर्ण **dst, ध्रुव वर्ण *s)
{
	*dst = s == रिक्त ? रिक्त : xstrdup(s);
}

स्थिर वर्ण **
new_string_array(u_int n)
{
	प्रत्यागम xcalloc(n, परिमाण(वर्ण *));
}

स्थिर शून्य
समुच्चयः_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->अङ्कः_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_आवरणम् = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	समुच्चयः_string(&o->permit_user_env_allowlist, "");
	o->rekey_सीमा = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	समुच्चयः_string(&o->routing_domain, "");
	समुच्चयः_string(&o->banner, रिक्त);
	समुच्चयः_string(&o->adm_forced_command, "internal-sftp");
	समुच्चयः_string(&o->chroot_directory, "");
	समुच्चयः_string(&o->host_कुञ्चिका_agent, रिक्त);
	समुच्चयः_string(&o->authorized_कुञ्चिकाः_command, "/bin/echo");
	समुच्चयः_string(&o->authorized_कुञ्चिकाः_command_user, "");
	समुच्चयः_string(&o->authorized_principals_file, रिक्त);

	o->अङ्कः_authkeys_files = 3;
	o->authorized_कुञ्चिकाः_files = new_string_array(o->अङ्कः_authkeys_files);
	समुच्चयः_string(&o->authorized_कुञ्चिकाः_files[0], रिक्त);
	समुच्चयः_string(&o->authorized_कुञ्चिकाः_files[1], "");
	समुच्चयः_string(&o->authorized_कुञ्चिकाः_files[2], ".ssh/authorized_keys");

	o->अङ्कः_log_verbose = 2;
	o->log_verbose = new_string_array(o->अङ्कः_log_verbose);
	समुच्चयः_string(&o->log_verbose[0], रिक्त);
	समुच्चयः_string(&o->log_verbose[1], "kex.c:*");

	o->अङ्कः_host_कुञ्चिका_files = 3;
	o->host_कुञ्चिका_file_userprovided =
	    xcalloc(o->अङ्कः_host_कुञ्चिका_files,
	    परिमाण(*o->host_कुञ्चिका_file_userprovided));
	o->host_कुञ्चिका_files = new_string_array(o->अङ्कः_host_कुञ्चिका_files);
	o->host_कुञ्चिका_file_userprovided[0] = 0;
	o->host_कुञ्चिका_file_userprovided[1] = 1;
	o->host_कुञ्चिका_file_userprovided[2] = -1;
	समुच्चयः_string(&o->host_कुञ्चिका_files[0], रिक्त);
	समुच्चयः_string(&o->host_कुञ्चिका_files[1], "");
	समुच्चयः_string(&o->host_कुञ्चिका_files[2], "/tmp/ssh_host_ed25519_key");

	o->अङ्कः_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->अङ्कः_queued_listens,
	    परिमाण(*o->queued_listen_addrs));
	समुच्चयः_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].पत्तनम् = 2222;
	समुच्चयः_string(&o->queued_listen_addrs[0].rdomain, रिक्त);
	समुच्चयः_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].पत्तनम् = -1;
	समुच्चयः_string(&o->queued_listen_addrs[1].rdomain, "");

	o->अङ्कः_subsystems = 2;
	o->subsystem_name = new_string_array(o->अङ्कः_subsystems);
	o->subsystem_command = new_string_array(o->अङ्कः_subsystems);
	o->subsystem_तर्काः = new_string_array(o->अङ्कः_subsystems);
	समुच्चयः_string(&o->subsystem_name[0], "sftp");
	समुच्चयः_string(&o->subsystem_command[0], "internal-sftp");
	समुच्चयः_string(&o->subsystem_तर्काः[0], "internal-sftp -f AUTH");
	समुच्चयः_string(&o->subsystem_name[1], "echo");
	समुच्चयः_string(&o->subsystem_command[1], "/bin/echo");
	समुच्चयः_string(&o->subsystem_तर्काः[1], "/bin/echo hello");
}

स्थिर शून्य
check_roundtrip(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions बहिर्गमनम्;

	initialize_server_options(&बहिर्गमनम्);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(deserialise_server_options(buf, &बहिर्गमनम्), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_ports, 2);
	ASSERT_INT_EQ(बहिर्गमनम्.ports[0], 22);
	ASSERT_INT_EQ(बहिर्गमनम्.ports[1], 2022);
	ASSERT_INT_EQ(बहिर्गमनम्.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(बहिर्गमनम्.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(बहिर्गमनम्.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(बहिर्गमनम्.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(बहिर्गमनम्.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(बहिर्गमनम्.fwd_opts.streamlocal_bind_आवरणम्, 0177);
	ASSERT_INT_EQ(बहिर्गमनम्.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(बहिर्गमनम्.permit_user_env, 1);
	ASSERT_STRING_EQ(बहिर्गमनम्.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(बहिर्गमनम्.rekey_सीमा, 123456789);
	ASSERT_INT_EQ(बहिर्गमनम्.rekey_interval, 600);
	ASSERT_U64_EQ(बहिर्गमनम्.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(बहिर्गमनम्.routing_domain, "");
	ASSERT_PTR_EQ(बहिर्गमनम्.banner, रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(बहिर्गमनम्.chroot_directory, "");
	ASSERT_PTR_EQ(बहिर्गमनम्.host_कुञ्चिका_agent, रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.authorized_कुञ्चिकाः_command, "/bin/echo");
	ASSERT_STRING_EQ(बहिर्गमनम्.authorized_कुञ्चिकाः_command_user, "");
	ASSERT_PTR_EQ(बहिर्गमनम्.authorized_principals_file, रिक्त);

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_authkeys_files, 3);
	ASSERT_PTR_EQ(बहिर्गमनम्.authorized_कुञ्चिकाः_files[0], रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.authorized_कुञ्चिकाः_files[1], "");
	ASSERT_STRING_EQ(बहिर्गमनम्.authorized_कुञ्चिकाः_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_log_verbose, 2);
	ASSERT_PTR_EQ(बहिर्गमनम्.log_verbose[0], रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_host_कुञ्चिका_files, 3);
	ASSERT_INT_EQ(बहिर्गमनम्.host_कुञ्चिका_file_userprovided[0], 0);
	ASSERT_INT_EQ(बहिर्गमनम्.host_कुञ्चिका_file_userprovided[1], 1);
	ASSERT_INT_EQ(बहिर्गमनम्.host_कुञ्चिका_file_userprovided[2], -1);
	ASSERT_PTR_EQ(बहिर्गमनम्.host_कुञ्चिका_files[0], रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.host_कुञ्चिका_files[1], "");
	ASSERT_STRING_EQ(बहिर्गमनम्.host_कुञ्चिका_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_queued_listens, 2);
	ASSERT_STRING_EQ(बहिर्गमनम्.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(बहिर्गमनम्.queued_listen_addrs[0].पत्तनम्, 2222);
	ASSERT_PTR_EQ(बहिर्गमनम्.queued_listen_addrs[0].rdomain, रिक्त);
	ASSERT_STRING_EQ(बहिर्गमनम्.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(बहिर्गमनम्.queued_listen_addrs[1].पत्तनम्, -1);
	ASSERT_STRING_EQ(बहिर्गमनम्.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(बहिर्गमनम्.अङ्कः_subsystems, 2);
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_तर्काः[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(बहिर्गमनम्.subsystem_तर्काः[1], "/bin/echo hello");

	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_trailing_दत्त(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions बहिर्गमनम्;
	पूर्णाङ्क r;

	initialize_server_options(&बहिर्गमनम्);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &बहिर्गमनम्);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_bad_संस्करणम्(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions बहिर्गमनम्;
	पूर्णाङ्क r;

	initialize_server_options(&बहिर्गमनम्);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), रिक्त);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &बहिर्गमनम्);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
check_rejects_bad_पत्तनम्_गणनम्(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions बहिर्गमनम्;
	पूर्णाङ्क r;

	initialize_server_options(&बहिर्गमनम्);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_आकार_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), रिक्त);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &बहिर्गमनम्);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
check_roundtrip_signed_limits(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	ServerOptions बहिर्गमनम्, अन्तर्;

	initialize_server_options(&बहिर्गमनम्);
	अन्तर् = *o;
	अन्तर्.fwd_opts.streamlocal_bind_आवरणम् = (बहुलकम्_t)-1;
	अन्तर्.ip_qos_bulk = INT_MIN;
	अन्तर्.rekey_सीमा = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&अन्तर्, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	ASSERT_INT_EQ(deserialise_server_options(buf, &बहिर्गमनम्), 0);
	ASSERT_INT_EQ(बहिर्गमनम्.fwd_opts.streamlocal_bind_आवरणम् == (बहुलकम्_t)-1, 1);
	ASSERT_INT_EQ(बहिर्गमनम्.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(बहिर्गमनम्.rekey_सीमा, INT64_MIN);
	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
attempt_deserialise_blob(ध्रुव u_char *p, आकार_t len)
{
	संरचना sshbuf *buf;
	ServerOptions बहिर्गमनम्;

	initialize_server_options(&बहिर्गमनम्);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), रिक्त);
	(शून्य)deserialise_server_options(buf, &बहिर्गमनम्);
	free_server_options(&बहिर्गमनम्);
	sshbuf_free(buf);
}

स्थिर शून्य
check_fuzz_deserialise(ध्रुव ServerOptions *o)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_अन्तः;

	यदि (test_is_fast())
		fuzzers &= ~FUZZ_1_BIT_FLIP;
	यदि (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, रिक्त);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	प्रति (; !fuzz_समाप्तम्(fuzz); fuzz_अग्र(fuzz))
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
	समुच्चयः_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_समाप्तम्();

	TEST_START("server options reject trailing data");
	समुच्चयः_test_options(&o);
	check_rejects_trailing_दत्त(&o);
	free_server_options(&o);
	TEST_समाप्तम्();

	TEST_START("server options reject unsupported version");
	समुच्चयः_test_options(&o);
	check_rejects_bad_संस्करणम्(&o);
	free_server_options(&o);
	TEST_समाप्तम्();

	TEST_START("server options reject bad port count");
	समुच्चयः_test_options(&o);
	check_rejects_bad_पत्तनम्_गणनम्(&o);
	free_server_options(&o);
	TEST_समाप्तम्();

	TEST_START("server options round trip signed limits");
	समुच्चयः_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_समाप्तम्();

	TEST_START("server options deserialise fuzz");
	समुच्चयः_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_समाप्तम्();
}

शून्य
benchmarks(शून्य)
{
	प्रारूप_लिख("no benchmarks\n");
}
