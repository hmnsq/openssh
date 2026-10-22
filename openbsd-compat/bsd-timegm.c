/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
  adapted for Samba4 by Andrew Tridgell
*/

#अन्तर्भाव "includes.h"

#अन्तर्भाव <time.h>

#ifndef HAVE_TIMEGM

स्थिर पूर्णाङ्क is_leap(अचिन्हित y)
{
	y += 1900;
	फर्काऊ (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

समय_प्रकार timegm(संरचना पंचांग *पंचांग)
{
	स्थिर अचर अचिन्हित ndays[2][12] ={
		{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
		{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};
	समय_प्रकार res = 0;
	अचिन्हित i;

	यदि (पंचांग->tm_mon > 12 ||
	    पंचांग->tm_mon < 0 ||
	    पंचांग->tm_mday > 31 ||
	    पंचांग->tm_min > 60 ||
	    पंचांग->tm_sec > 60 ||
	    पंचांग->tm_hour > 24) {
		/* invalid tm structure */
		फर्काऊ 0;
	}

	लागि (i = 70; i < पंचांग->tm_year; ++i)
		res += is_leap(i) ? 366 : 365;

	लागि (i = 0; i < पंचांग->tm_mon; ++i)
		res += ndays[is_leap(पंचांग->tm_year)][i];
	res += पंचांग->tm_mday - 1;
	res *= 24;
	res += पंचांग->tm_hour;
	res *= 60;
	res += पंचांग->tm_min;
	res *= 60;
	res += पंचांग->tm_sec;
	फर्काऊ res;
}
#endif /* HAVE_TIMEGM */
