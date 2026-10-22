/*	$OpenBSD: rijndael.h,v 1.15 2021/09/28 11:14:50 dtucker Exp $ */

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _PRIVATE_RIJNDAEL_H
#define _PRIVATE_RIJNDAEL_H

#define AES_MAXKEYBITS	(256)
#define AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#define AES_MAXROUNDS	14

ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned ଅକ୍ଷର	u8;
ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned short	u16;
ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା	u32;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	rijndael_ଚାବି_Setup_Enc(unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା [], ଅଚଳ unsigned ଅକ୍ଷର [], ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	rijndaelEncrypt(ଅଚଳ unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା [], ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ u8 [16], u8 [16]);

/*  The structure for key information */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	decrypt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	Nr;		/* key-length-dependent number of rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u32	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

ଶୂନ୍ୟ	 rijndael_set_ଚାବି(rijndael_ctx *, u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 rijndael_decrypt(rijndael_ctx *, u_char *, u_char *);
ଶୂନ୍ୟ	 rijndael_encrypt(rijndael_ctx *, u_char *, u_char *);

#endif /* _PRIVATE_RIJNDAEL_H */
