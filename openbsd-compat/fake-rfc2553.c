/*
 * Copyright (C) 2000-2003 Damien Miller.  All rights reserved.
 * Copyright (C) 1999 WIDE Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Pseudo-implementation of RFC2553 name / address resolution functions
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For example, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#समावेश "includes.h"

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#अगर_अघोषित HAVE_GETNAMEINFO
पूर्णांक getnameinfo(स्थिर काष्ठा sockaddr *sa, माप_प्रकार salen, अक्षर *host,
		माप_प्रकार hostlen, अक्षर *serv, माप_प्रकार servlen, पूर्णांक flags)
{
	काष्ठा sockaddr_in *sin = (काष्ठा sockaddr_in *)sa;
	काष्ठा hostent *hp;
	अक्षर tmpserv[16];

	अगर ((sa->sa_family != AF_UNSPEC && sa->sa_family != AF_INET) ||
	    salen < माप(काष्ठा sockaddr_in))
		वापस (EAI_FAMILY);
	अगर (serv != शून्य) {
		snprintf(tmpserv, माप(tmpserv), "%d", ntohs(sin->sin_port));
		अगर (strlcpy(serv, tmpserv, servlen) >= servlen)
			वापस (EAI_MEMORY);
	}

	अगर (host != शून्य) {
		अगर (flags & NI_NUMERICHOST) {
			अगर (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				वापस (EAI_MEMORY);
			अन्यथा
				वापस (0);
		} अन्यथा {
			hp = gethostbyaddr((अक्षर *)&sin->sin_addr,
			    माप(काष्ठा in_addr), AF_INET);
			अगर (hp == शून्य)
				वापस (EAI_NODATA);

			अगर (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				वापस (EAI_MEMORY);
			अन्यथा
				वापस (0);
		}
	}
	वापस (0);
}
#पूर्ण_अगर /* !HAVE_GETNAMEINFO */

#अगर_अघोषित HAVE_GAI_STRERROR
#अगर_घोषित HAVE_CONST_GAI_STRERROR_PROTO
स्थिर अक्षर *
#अन्यथा
अक्षर *
#पूर्ण_अगर
gai_strerror(पूर्णांक err)
{
	चयन (err) {
	हाल EAI_NODATA:
		वापस ("no address associated with name");
	हाल EAI_MEMORY:
		वापस ("memory allocation failure");
	हाल EAI_NONAME:
		वापस ("name or service is not known");
	हाल EAI_FAMILY:
		वापस ("ai_family not supported");
	शेष:
		वापस ("unknown/invalid error");
	}
}
#पूर्ण_अगर /* !HAVE_GAI_STRERROR */

#अगर_अघोषित HAVE_FREEADDRINFO
व्योम
freeaddrinfo(काष्ठा addrinfo *ai)
{
	काष्ठा addrinfo *अग्र;

	क्रम(; ai != शून्य;) {
		अग्र = ai->ai_next;
		मुक्त(ai);
		ai = अग्र;
	}
}
#पूर्ण_अगर /* !HAVE_FREEADDRINFO */

#अगर_अघोषित HAVE_GETADDRINFO
अटल काष्ठा
addrinfo *malloc_ai(पूर्णांक port, u_long addr, स्थिर काष्ठा addrinfo *hints)
{
	काष्ठा addrinfo *ai;

	ai = दो_स्मृति(माप(*ai) + माप(काष्ठा sockaddr_in));
	अगर (ai == शून्य)
		वापस (शून्य);

	स_रखो(ai, '\0', माप(*ai) + माप(काष्ठा sockaddr_in));

	ai->ai_addr = (काष्ठा sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = माप(काष्ठा sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((काष्ठा sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((काष्ठा sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;

	/* XXX: the following is not generally correct, but does what we want */
	अगर (hints->ai_socktype)
		ai->ai_socktype = hints->ai_socktype;
	अन्यथा
		ai->ai_socktype = SOCK_STREAM;

	अगर (hints->ai_protocol)
		ai->ai_protocol = hints->ai_protocol;

	वापस (ai);
}

पूर्णांक
getaddrinfo(स्थिर अक्षर *hostname, स्थिर अक्षर *servname,
    स्थिर काष्ठा addrinfo *hints, काष्ठा addrinfo **res)
{
	काष्ठा hostent *hp;
	काष्ठा servent *sp;
	काष्ठा in_addr in;
	पूर्णांक i;
	दीर्घ पूर्णांक port;
	u_long addr;

	port = 0;
	अगर (hints && hints->ai_family != AF_UNSPEC &&
	    hints->ai_family != AF_INET)
		वापस (EAI_FAMILY);
	अगर (servname != शून्य) {
		अक्षर *cp;

		port = म_से_दीर्घ(servname, &cp, 10);
		अगर (port > 0 && port <= 65535 && *cp == '\0')
			port = htons(port);
		अन्यथा अगर ((sp = getservbyname(servname, शून्य)) != शून्य)
			port = sp->s_port;
		अन्यथा
			port = 0;
	}

	अगर (hints && hints->ai_flags & AI_PASSIVE) {
		addr = htonl(0x00000000);
		अगर (hostname && inet_aton(hostname, &in) != 0)
			addr = in.s_addr;
		*res = malloc_ai(port, addr, hints);
		अगर (*res == शून्य)
			वापस (EAI_MEMORY);
		वापस (0);
	}

	अगर (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001), hints);
		अगर (*res == शून्य)
			वापस (EAI_MEMORY);
		वापस (0);
	}

	अगर (inet_aton(hostname, &in)) {
		*res = malloc_ai(port, in.s_addr, hints);
		अगर (*res == शून्य)
			वापस (EAI_MEMORY);
		वापस (0);
	}

	/* Don't try DNS if AI_NUMERICHOST is set */
	अगर (hints && hints->ai_flags & AI_NUMERICHOST)
		वापस (EAI_NONAME);

	hp = gethostbyname(hostname);
	अगर (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		काष्ठा addrinfo *cur, *पूर्व;

		cur = पूर्व = *res = शून्य;
		क्रम (i = 0; hp->h_addr_list[i]; i++) {
			काष्ठा in_addr *in = (काष्ठा in_addr *)hp->h_addr_list[i];

			cur = malloc_ai(port, in->s_addr, hints);
			अगर (cur == शून्य) {
				अगर (*res != शून्य)
					freeaddrinfo(*res);
				वापस (EAI_MEMORY);
			}
			अगर (पूर्व)
				पूर्व->ai_next = cur;
			अन्यथा
				*res = cur;

			पूर्व = cur;
		}
		वापस (0);
	}

	वापस (EAI_NODATA);
}
#पूर्ण_अगर /* !HAVE_GETADDRINFO */
