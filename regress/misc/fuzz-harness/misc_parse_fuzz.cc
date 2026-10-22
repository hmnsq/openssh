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

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <sys/types.h>

बाह्य "C" {
#अन्तर्भाव "addr.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"
}

स्थिर पूर्णांक log_initialized = 0;

स्थिर अक्षर *
dup_n(स्थिरांक uint8_t *body, माप_प्रकार blen)
{
	अक्षर *s = (अक्षर *)दो_स्मृति(blen + 1);
	जर (s == रिक्त)
		परत रिक्त;
	स_नकल(s, body, blen);
	s[blen] = '\0';
	परत s;
}

स्थिर शून्य
split_two(स्थिरांक uint8_t *body, माप_प्रकार blen, अक्षर **a, अक्षर **b)
{
	स्थिरांक uint8_t *nul = (स्थिरांक uint8_t *)स_प्रथम(body, 0, blen);
	*a = रिक्त;
	*b = रिक्त;
	जर (nul == रिक्त) {
		*a = dup_n(body, blen);
		*b = strdup("");
		परत;
	}
	माप_प्रकार alen = (माप_प्रकार)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	जर (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	जर (size == 0)
		परत 0;

	अक्षर *s = dup_n(data, size);
	अक्षर *a = रिक्त, *b = रिक्त;
	split_two(data, size, &a, &b);
	जर (s == रिक्त || a == रिक्त || b == रिक्त) {
		मुक्त(s);
		मुक्त(a);
		मुक्त(b);
		परत 0;
	}

	{
		अक्षर *u = रिक्त, *h = रिक्त;
		पूर्णांक port = 0;
		जर (parse_user_host_port(s, &u, &h, &port) == 0) {
			मुक्त(u);
			मुक्त(h);
		}
	}
	{
		अक्षर *u = रिक्त, *h = रिक्त, *p = रिक्त;
		पूर्णांक port = 0;
		जर (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			मुक्त(u);
			मुक्त(h);
			मुक्त(p);
		}
	}
	(शून्य)convtime(s);
	(शून्य)a2port(s);
	{
		पूर्णांक tun = 0;
		(शून्य)a2tun(s, &tun);
	}
	{
		पूर्णांक ac = 0;
		अक्षर **av = रिक्त;
		जर (argv_split(s, &ac, &av, 1) == 0) {
			अक्षर *back = argv_assemble(ac, av);
			मुक्त(back);
			argv_free(av, ac);
		}
	}
	{
		स्थिरांक अक्षर *err = रिक्त;
		(शून्य)valid_domain(s, 0, &err);
	}
	(शून्य)valid_env_name(s);
	{
		uint64_t t = 0;
		(शून्य)parse_absolute_time(s, &t);
	}

	{
		संरचना xaddr n;
		(शून्य)addr_pton(s, &n);
	}
	{
		संरचना xaddr n;
		u_int prefix = 0;
		(शून्य)addr_pton_cidr(s, &n, &prefix);
	}

	(शून्य)addr_match_list(a, b);
	(शून्य)addr_match_cidr_list(a, b);
	(शून्य)match_pattern(a, b);
	(शून्य)match_pattern_list(a, b, 0);
	(शून्य)match_hostname(a, b);
	(शून्य)match_host_and_ip(a, "127.0.0.1", b);
	(शून्य)match_user("fuzz", a, "127.0.0.1", b);

	मुक्त(s);
	मुक्त(a);
	मुक्त(b);
	परत 0;
}
