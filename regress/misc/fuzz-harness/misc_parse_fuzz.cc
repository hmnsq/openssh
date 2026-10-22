/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for small string-input parsers across OpenSSH
 *
 * Targets: misc.c, addr.c, addrmatch.c, match.c
 *
 * Threat model:
 * - User-supplied CLI arguments (user@host:port, ssh:// URIs, port and
 *   tunnel numbers)
 * - Admin-supplied patterns in sshd_config / ssh_config (Match Address
 *   CIDR lists, AllowUsers / DenyUsers, AllowGroups, hostname patterns)
 *
 * All targeted functions are pure (no inter-call state). Each iteration
 * invokes every parser exactly once on the same fuzz body in a fixed
 * source order. The body is split into two substrings at the first
 * embedded NUL so two-argument matchers can mutate either side.
 *
 * Parsers covered:
 * - parse_user_host_port, parse_uri, convtime, a2port, a2tun,
 *   argv_split + argv_assemble, valid_domain, valid_env_name,
 *   parse_absolute_time (misc.c)
 * - addr_pton, addr_pton_cidr (addr.c)
 * - addr_match_list, addr_match_cidr_list (addrmatch.c)
 * - match_pattern, match_pattern_list, match_hostname,
 *   match_host_and_ip, match_user (match.c)
 */

#समावेश <stdio.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <sys/types.h>

बाह्य "C" {
#समावेश "addr.h"
#समावेश "match.h"
#समावेश "misc.h"
#समावेश "log.h"
}

अटल पूर्णांक log_initialized = 0;

अटल अक्षर *
dup_n(स्थिर uint8_t *body, माप_प्रकार blen)
{
	अक्षर *s = (अक्षर *)दो_स्मृति(blen + 1);
	अगर (s == शून्य)
		वापस शून्य;
	स_नकल(s, body, blen);
	s[blen] = '\0';
	वापस s;
}

अटल व्योम
split_two(स्थिर uint8_t *body, माप_प्रकार blen, अक्षर **a, अक्षर **b)
{
	स्थिर uint8_t *nul = (स्थिर uint8_t *)स_प्रथम(body, 0, blen);
	*a = शून्य;
	*b = शून्य;
	अगर (nul == शून्य) {
		*a = dup_n(body, blen);
		*b = strdup("");
		वापस;
	}
	माप_प्रकार alen = (माप_प्रकार)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	अगर (आकार == 0)
		वापस 0;

	अक्षर *s = dup_n(तथ्य, आकार);
	अक्षर *a = शून्य, *b = शून्य;
	split_two(तथ्य, आकार, &a, &b);
	अगर (s == शून्य || a == शून्य || b == शून्य) {
		मुक्त(s);
		मुक्त(a);
		मुक्त(b);
		वापस 0;
	}

	{
		अक्षर *u = शून्य, *h = शून्य;
		पूर्णांक port = 0;
		अगर (parse_user_host_port(s, &u, &h, &port) == 0) {
			मुक्त(u);
			मुक्त(h);
		}
	}
	{
		अक्षर *u = शून्य, *h = शून्य, *p = शून्य;
		पूर्णांक port = 0;
		अगर (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			मुक्त(u);
			मुक्त(h);
			मुक्त(p);
		}
	}
	(व्योम)convtime(s);
	(व्योम)a2port(s);
	{
		पूर्णांक tun = 0;
		(व्योम)a2tun(s, &tun);
	}
	{
		पूर्णांक ac = 0;
		अक्षर **av = शून्य;
		अगर (argv_split(s, &ac, &av, 1) == 0) {
			अक्षर *back = argv_assemble(ac, av);
			मुक्त(back);
			argv_free(av, ac);
		}
	}
	{
		स्थिर अक्षर *err = शून्य;
		(व्योम)valid_domain(s, 0, &err);
	}
	(व्योम)valid_env_name(s);
	{
		uint64_t t = 0;
		(व्योम)parse_absolute_time(s, &t);
	}

	{
		काष्ठा xaddr n;
		(व्योम)addr_pton(s, &n);
	}
	{
		काष्ठा xaddr n;
		u_int prefix = 0;
		(व्योम)addr_pton_cidr(s, &n, &prefix);
	}

	(व्योम)addr_match_list(a, b);
	(व्योम)addr_match_cidr_list(a, b);
	(व्योम)match_pattern(a, b);
	(व्योम)match_pattern_list(a, b, 0);
	(व्योम)match_hostname(a, b);
	(व्योम)match_host_and_ip(a, "127.0.0.1", b);
	(व्योम)match_user("fuzz", a, "127.0.0.1", b);

	मुक्त(s);
	मुक्त(a);
	मुक्त(b);
	वापस 0;
}
