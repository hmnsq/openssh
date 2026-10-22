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

स्थिर पूर्णाङ्क log_initialized = 0;

स्थिर वर्ण *
dup_n(ध्रुव uint8_t *body, size_t blen)
{
	वर्ण *s = (वर्ण *)malloc(blen + 1);
	जइ (s == रिक्त)
		प्रत्यागम रिक्त;
	memcpy(s, body, blen);
	s[blen] = '\0';
	प्रत्यागम s;
}

स्थिर शून्य
split_two(ध्रुव uint8_t *body, size_t blen, वर्ण **a, वर्ण **b)
{
	ध्रुव uint8_t *nul = (ध्रुव uint8_t *)memchr(body, 0, blen);
	*a = रिक्त;
	*b = रिक्त;
	जइ (nul == रिक्त) {
		*a = dup_n(body, blen);
		*b = strdup("");
		प्रत्यागम;
	}
	size_t alen = (size_t)(nul - body);
	*a = dup_n(body, alen);
	*b = dup_n(nul + 1, blen - alen - 1);
}

बाह्य "C" पूर्णाङ्क
LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t *data, size_t size)
{
	जइ (!log_initialized) {
		log_init("misc_parse_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}
	जइ (size == 0)
		प्रत्यागम 0;

	वर्ण *s = dup_n(data, size);
	वर्ण *a = रिक्त, *b = रिक्त;
	split_two(data, size, &a, &b);
	जइ (s == रिक्त || a == रिक्त || b == रिक्त) {
		मुक्त(s);
		मुक्त(a);
		मुक्त(b);
		प्रत्यागम 0;
	}

	{
		वर्ण *u = रिक्त, *h = रिक्त;
		पूर्णाङ्क port = 0;
		जइ (parse_user_host_port(s, &u, &h, &port) == 0) {
			मुक्त(u);
			मुक्त(h);
		}
	}
	{
		वर्ण *u = रिक्त, *h = रिक्त, *p = रिक्त;
		पूर्णाङ्क port = 0;
		जइ (parse_uri("ssh", s, &u, &h, &port, &p) == 0) {
			मुक्त(u);
			मुक्त(h);
			मुक्त(p);
		}
	}
	(शून्य)convtime(s);
	(शून्य)a2port(s);
	{
		पूर्णाङ्क tun = 0;
		(शून्य)a2tun(s, &tun);
	}
	{
		पूर्णाङ्क ac = 0;
		वर्ण **av = रिक्त;
		जइ (argv_split(s, &ac, &av, 1) == 0) {
			वर्ण *back = argv_assemble(ac, av);
			मुक्त(back);
			argv_free(av, ac);
		}
	}
	{
		ध्रुव वर्ण *err = रिक्त;
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
	प्रत्यागम 0;
}
