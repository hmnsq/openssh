/*	$OpenBSD: tree.h,v 1.13 2011/07/09 00:19:45 pirofti Exp $	*/
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: sys/sys/tree.h */

#అన్తర్భావ "config.h"
#నిర్వచితమైతే NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే	SYS_వృక్షం_H
#నిర్వచించు	SYS_వృక్షం_H

/*
 * This file defines data structures for different types of trees:
 * splay trees and red-black trees.
 *
 * A splay tree is a self-organizing data structure.  Every operation
 * on the tree causes a splay to happen.  The splay moves the requested
 * node to the root of the tree and partly rebalances it.
 *
 * This has the benefit that request locality causes faster lookups as
 * the requested nodes move to the top of the tree.  On the other hand,
 * every lookup causes memory writes.
 *
 * The Balance Theorem bounds the total access time for m operations
 * and n inserts on an initially empty tree as O((m + n)lg n).  The
 * amortized cost for a sequence of m accesses to a splay tree is O(lg n);
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *	- every search path from the root to a leaf consists of the
 *	  same number of black nodes,
 *	- each red node (except for the root) has a black parent,
 *	- each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

#నిర్వచించు SPLAY_తల(name, type)						\
నిర్మాణం name {								\
	నిర్మాణం type *sph_మూలం; /* root of the tree */			\
}

#నిర్వచించు SPLAY_INITIALIZER(మూలం)						\
	{ ఖాళీ }

#నిర్వచించు SPLAY_INIT(మూలం) చేయి {						\
	(మూలం)->sph_మూలం = ఖాళీ;					\
} అయితే (0)

#నిర్వచించు SPLAY_నమోదు(type)						\
నిర్మాణం {								\
	నిర్మాణం type *spe_ఎడమ; /* left element */			\
	నిర్మాణం type *spe_కుడి; /* right element */			\
}

#నిర్వచించు SPLAY_ఎడమ(elm, క్షేత్రం)		(elm)->క్షేత్రం.spe_ఎడమ
#నిర్వచించు SPLAY_కుడి(elm, క్షేత్రం)		(elm)->క్షేత్రం.spe_కుడి
#నిర్వచించు SPLAY_మూలం(తల)		(తల)->sph_మూలం
#నిర్వచించు SPLAY_ఖాళీలు(తల)		(SPLAY_మూలం(తల) == ఖాళీ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#నిర్వచించు SPLAY_ROTATE_కుడి(తల, tmp, క్షేత్రం) చేయి {			\
	SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) = SPLAY_కుడి(tmp, క్షేత్రం);	\
	SPLAY_కుడి(tmp, క్షేత్రం) = (తల)->sph_మూలం;			\
	(తల)->sph_మూలం = tmp;						\
} అయితే (0)
	
#నిర్వచించు SPLAY_ROTATE_ఎడమ(తల, tmp, క్షేత్రం) చేయి {			\
	SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) = SPLAY_ఎడమ(tmp, క్షేత్రం);	\
	SPLAY_ఎడమ(tmp, క్షేత్రం) = (తల)->sph_మూలం;			\
	(తల)->sph_మూలం = tmp;						\
} అయితే (0)

#నిర్వచించు SPLAY_LINKLEFT(తల, tmp, క్షేత్రం) చేయి {				\
	SPLAY_ఎడమ(tmp, క్షేత్రం) = (తల)->sph_మూలం;			\
	tmp = (తల)->sph_మూలం;						\
	(తల)->sph_మూలం = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);		\
} అయితే (0)

#నిర్వచించు SPLAY_LINKRIGHT(తల, tmp, క్షేత్రం) చేయి {				\
	SPLAY_కుడి(tmp, క్షేత్రం) = (తల)->sph_మూలం;			\
	tmp = (తల)->sph_మూలం;						\
	(తల)->sph_మూలం = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);	\
} అయితే (0)

#నిర్వచించు SPLAY_ASSEMBLE(తల, కణుపు, ఎడమ, కుడి, క్షేత్రం) చేయి {		\
	SPLAY_కుడి(ఎడమ, క్షేత్రం) = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);	\
	SPLAY_ఎడమ(కుడి, క్షేత్రం) = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);\
	SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) = SPLAY_కుడి(కణుపు, క్షేత్రం);	\
	SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) = SPLAY_ఎడమ(కణుపు, క్షేత్రం);	\
} అయితే (0)

/* Generates prototypes and inline functions */

#నిర్వచించు SPLAY_PROTOTYPE(name, type, క్షేత్రం, cmp)				\
శూన్య name##_SPLAY(నిర్మాణం name *, నిర్మాణం type *);			\
శూన్య name##_SPLAY_MINMAX(నిర్మాణం name *, పూర్ణాంకం);				\
నిర్మాణం type *name##_SPLAY_INSERT(నిర్మాణం name *, నిర్మాణం type *);		\
నిర్మాణం type *name##_SPLAY_REMOVE(నిర్మాణం name *, నిర్మాణం type *);		\
									\
/* Finds the node with the same key as elm */				\
స్థిర __inline నిర్మాణం type *						\
name##_SPLAY_FIND(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	ఒకవేళ (SPLAY_ఖాళీలు(తల))						\
		తిరిగి(ఖాళీ);						\
	name##_SPLAY(తల, elm);					\
	ఒకవేళ ((cmp)(elm, (తల)->sph_మూలం) == 0)				\
		తిరిగి (తల->sph_మూలం);				\
	తిరిగి (ఖాళీ);							\
}									\
									\
స్థిర __inline నిర్మాణం type *						\
name##_SPLAY_NEXT(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	name##_SPLAY(తల, elm);					\
	ఒకవేళ (SPLAY_కుడి(elm, క్షేత్రం) != ఖాళీ) {				\
		elm = SPLAY_కుడి(elm, క్షేత్రం);				\
		అయితే (SPLAY_ఎడమ(elm, క్షేత్రం) != ఖాళీ) {		\
			elm = SPLAY_ఎడమ(elm, క్షేత్రం);			\
		}							\
	} లేకపోతే								\
		elm = ఖాళీ;						\
	తిరిగి (elm);							\
}									\
									\
స్థిర __inline నిర్మాణం type *						\
name##_SPLAY_MIN_MAX(నిర్మాణం name *తల, పూర్ణాంకం val)			\
{									\
	name##_SPLAY_MINMAX(తల, val);					\
        తిరిగి (SPLAY_మూలం(తల));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#నిర్వచించు SPLAY_GENERATE(name, type, క్షేత్రం, cmp)				\
నిర్మాణం type *								\
name##_SPLAY_INSERT(నిర్మాణం name *తల, నిర్మాణం type *elm)		\
{									\
    ఒకవేళ (SPLAY_ఖాళీలు(తల)) {						\
	    SPLAY_ఎడమ(elm, క్షేత్రం) = SPLAY_కుడి(elm, క్షేత్రం) = ఖాళీ;	\
    } లేకపోతే {								\
	    పూర్ణాంకం __comp;							\
	    name##_SPLAY(తల, elm);					\
	    __comp = (cmp)(elm, (తల)->sph_మూలం);			\
	    ఒకవేళ(__comp < 0) {						\
		    SPLAY_ఎడమ(elm, క్షేత్రం) = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);\
		    SPLAY_కుడి(elm, క్షేత్రం) = (తల)->sph_మూలం;		\
		    SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) = ఖాళీ;		\
	    } లేకపోతే ఒకవేళ (__comp > 0) {					\
		    SPLAY_కుడి(elm, క్షేత్రం) = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);\
		    SPLAY_ఎడమ(elm, క్షేత్రం) = (తల)->sph_మూలం;		\
		    SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) = ఖాళీ;	\
	    } లేకపోతే							\
		    తిరిగి ((తల)->sph_మూలం);				\
    }									\
    (తల)->sph_మూలం = (elm);						\
    తిరిగి (ఖాళీ);							\
}									\
									\
నిర్మాణం type *								\
name##_SPLAY_REMOVE(నిర్మాణం name *తల, నిర్మాణం type *elm)		\
{									\
	నిర్మాణం type *__tmp;						\
	ఒకవేళ (SPLAY_ఖాళీలు(తల))						\
		తిరిగి (ఖాళీ);						\
	name##_SPLAY(తల, elm);					\
	ఒకవేళ ((cmp)(elm, (తల)->sph_మూలం) == 0) {			\
		ఒకవేళ (SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) == ఖాళీ) {	\
			(తల)->sph_మూలం = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);\
		} లేకపోతే {						\
			__tmp = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);	\
			(తల)->sph_మూలం = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);\
			name##_SPLAY(తల, elm);			\
			SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) = __tmp;	\
		}							\
		తిరిగి (elm);						\
	}								\
	తిరిగి (ఖాళీ);							\
}									\
									\
శూన్య									\
name##_SPLAY(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	నిర్మాణం type __node, *__left, *__right, *__tmp;			\
	పూర్ణాంకం __comp;							\
\
	SPLAY_ఎడమ(&__node, క్షేత్రం) = SPLAY_కుడి(&__node, క్షేత్రం) = ఖాళీ;\
	__left = __right = &__node;					\
\
	అయితే ((__comp = (cmp)(elm, (తల)->sph_మూలం))) {		\
		ఒకవేళ (__comp < 0) {					\
			__tmp = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);	\
			ఒకవేళ (__tmp == ఖాళీ)				\
				ఆపు;					\
			ఒకవేళ ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_కుడి(తల, __tmp, క్షేత్రం);	\
				ఒకవేళ (SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) == ఖాళీ)\
					ఆపు;				\
			}						\
			SPLAY_LINKLEFT(తల, __right, క్షేత్రం);		\
		} లేకపోతే ఒకవేళ (__comp > 0) {				\
			__tmp = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);	\
			ఒకవేళ (__tmp == ఖాళీ)				\
				ఆపు;					\
			ఒకవేళ ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ఎడమ(తల, __tmp, క్షేత్రం);	\
				ఒకవేళ (SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) == ఖాళీ)\
					ఆపు;				\
			}						\
			SPLAY_LINKRIGHT(తల, __left, క్షేత్రం);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(తల, &__node, __left, __right, క్షేత్రం);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
శూన్య name##_SPLAY_MINMAX(నిర్మాణం name *తల, పూర్ణాంకం __comp) \
{									\
	నిర్మాణం type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ఎడమ(&__node, క్షేత్రం) = SPLAY_కుడి(&__node, క్షేత్రం) = ఖాళీ;\
	__left = __right = &__node;					\
\
	అయితే (1) {							\
		ఒకవేళ (__comp < 0) {					\
			__tmp = SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం);	\
			ఒకవేళ (__tmp == ఖాళీ)				\
				ఆపు;					\
			ఒకవేళ (__comp < 0){				\
				SPLAY_ROTATE_కుడి(తల, __tmp, క్షేత్రం);	\
				ఒకవేళ (SPLAY_ఎడమ((తల)->sph_మూలం, క్షేత్రం) == ఖాళీ)\
					ఆపు;				\
			}						\
			SPLAY_LINKLEFT(తల, __right, క్షేత్రం);		\
		} లేకపోతే ఒకవేళ (__comp > 0) {				\
			__tmp = SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం);	\
			ఒకవేళ (__tmp == ఖాళీ)				\
				ఆపు;					\
			ఒకవేళ (__comp > 0) {				\
				SPLAY_ROTATE_ఎడమ(తల, __tmp, క్షేత్రం);	\
				ఒకవేళ (SPLAY_కుడి((తల)->sph_మూలం, క్షేత్రం) == ఖాళీ)\
					ఆపు;				\
			}						\
			SPLAY_LINKRIGHT(తల, __left, క్షేత్రం);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(తల, &__node, __left, __right, క్షేత్రం);		\
}

#నిర్వచించు SPLAY_NEGINF	-1
#నిర్వచించు SPLAY_INF	1

#నిర్వచించు SPLAY_చొప్పించు(name, x, y)	name##_SPLAY_INSERT(x, y)
#నిర్వచించు SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#నిర్వచించు SPLAY_కనుగొను(name, x, y)		name##_SPLAY_FIND(x, y)
#నిర్వచించు SPLAY_తదుపరి(name, x, y)		name##_SPLAY_NEXT(x, y)
#నిర్వచించు SPLAY_MIN(name, x)		(SPLAY_ఖాళీలు(x) ? ఖాళీ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#నిర్వచించు SPLAY_MAX(name, x)		(SPLAY_ఖాళీలు(x) ? ఖాళీ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#నిర్వచించు SPLAY_FOREACH(x, name, తల)					\
	కొరకు ((x) = SPLAY_MIN(name, తల);				\
	     (x) != ఖాళీ;						\
	     (x) = SPLAY_తదుపరి(name, తల, x))

/* Macros that define a red-black tree */
#నిర్వచించు RB_తల(name, type)						\
నిర్మాణం name {								\
	నిర్మాణం type *rbh_మూలం; /* root of the tree */			\
}

#నిర్వచించు RB_INITIALIZER(మూలం)						\
	{ ఖాళీ }

#నిర్వచించు RB_INIT(మూలం) చేయి {						\
	(మూలం)->rbh_మూలం = ఖాళీ;					\
} అయితే (0)

#నిర్వచించు RB_BLACK	0
#నిర్వచించు RB_RED		1
#నిర్వచించు RB_నమోదు(type)							\
నిర్మాణం {								\
	నిర్మాణం type *rbe_ఎడమ;		/* left element */		\
	నిర్మాణం type *rbe_కుడి;		/* right element */		\
	నిర్మాణం type *rbe_మాతృ;	/* parent element */		\
	పూర్ణాంకం rbe_color;			/* node color */		\
}

#నిర్వచించు RB_ఎడమ(elm, క్షేత్రం)		(elm)->క్షేత్రం.rbe_ఎడమ
#నిర్వచించు RB_కుడి(elm, క్షేత్రం)		(elm)->క్షేత్రం.rbe_కుడి
#నిర్వచించు RB_మాతృ(elm, క్షేత్రం)		(elm)->క్షేత్రం.rbe_మాతృ
#నిర్వచించు RB_COLOR(elm, క్షేత్రం)		(elm)->క్షేత్రం.rbe_color
#నిర్వచించు RB_మూలం(తల)			(తల)->rbh_మూలం
#నిర్వచించు RB_ఖాళీలు(తల)			(RB_మూలం(తల) == ఖాళీ)

#నిర్వచించు RB_సమితి(elm, మాతృ, క్షేత్రం) చేయి {					\
	RB_మాతృ(elm, క్షేత్రం) = మాతృ;					\
	RB_ఎడమ(elm, క్షేత్రం) = RB_కుడి(elm, క్షేత్రం) = ఖాళీ;		\
	RB_COLOR(elm, క్షేత్రం) = RB_RED;					\
} అయితే (0)

#నిర్వచించు RB_సమితి_BLACKRED(black, red, క్షేత్రం) చేయి {				\
	RB_COLOR(black, క్షేత్రం) = RB_BLACK;				\
	RB_COLOR(red, క్షేత్రం) = RB_RED;					\
} అయితే (0)

#నిర్వచితం_కాకపోతే RB_AUGMENT
#నిర్వచించు RB_AUGMENT(x)	చేయి {} అయితే (0)
#అయితే_ముగింపు

#నిర్వచించు RB_ROTATE_ఎడమ(తల, elm, tmp, క్షేత్రం) చేయి {			\
	(tmp) = RB_కుడి(elm, క్షేత్రం);					\
	ఒకవేళ ((RB_కుడి(elm, క్షేత్రం) = RB_ఎడమ(tmp, క్షేత్రం))) {		\
		RB_మాతృ(RB_ఎడమ(tmp, క్షేత్రం), క్షేత్రం) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ఒకవేళ ((RB_మాతృ(tmp, క్షేత్రం) = RB_మాతృ(elm, క్షేత్రం))) {		\
		ఒకవేళ ((elm) == RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం))	\
			RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం) = (tmp);	\
		లేకపోతే							\
			RB_కుడి(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం) = (tmp);	\
	} లేకపోతే								\
		(తల)->rbh_మూలం = (tmp);				\
	RB_ఎడమ(tmp, క్షేత్రం) = (elm);					\
	RB_మాతృ(elm, క్షేత్రం) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ఒకవేళ ((RB_మాతృ(tmp, క్షేత్రం)))					\
		RB_AUGMENT(RB_మాతృ(tmp, క్షేత్రం));			\
} అయితే (0)

#నిర్వచించు RB_ROTATE_కుడి(తల, elm, tmp, క్షేత్రం) చేయి {			\
	(tmp) = RB_ఎడమ(elm, క్షేత్రం);					\
	ఒకవేళ ((RB_ఎడమ(elm, క్షేత్రం) = RB_కుడి(tmp, క్షేత్రం))) {		\
		RB_మాతృ(RB_కుడి(tmp, క్షేత్రం), క్షేత్రం) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ఒకవేళ ((RB_మాతృ(tmp, క్షేత్రం) = RB_మాతృ(elm, క్షేత్రం))) {		\
		ఒకవేళ ((elm) == RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం))	\
			RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం) = (tmp);	\
		లేకపోతే							\
			RB_కుడి(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం) = (tmp);	\
	} లేకపోతే								\
		(తల)->rbh_మూలం = (tmp);				\
	RB_కుడి(tmp, క్షేత్రం) = (elm);					\
	RB_మాతృ(elm, క్షేత్రం) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ఒకవేళ ((RB_మాతృ(tmp, క్షేత్రం)))					\
		RB_AUGMENT(RB_మాతృ(tmp, క్షేత్రం));			\
} అయితే (0)

/* Generates prototypes and inline functions */
#నిర్వచించు	RB_PROTOTYPE(name, type, క్షేత్రం, cmp)				\
	RB_PROTOTYPE_అంతర్గత(name, type, క్షేత్రం, cmp,)
#నిర్వచించు	RB_PROTOTYPE_STATIC(name, type, క్షేత్రం, cmp)			\
	RB_PROTOTYPE_అంతర్గత(name, type, క్షేత్రం, cmp, __attribute__((__unused__)) స్థిర)
#నిర్వచించు RB_PROTOTYPE_అంతర్గత(name, type, క్షేత్రం, cmp, attr)		\
attr శూన్య name##_RB_INSERT_COLOR(నిర్మాణం name *, నిర్మాణం type *);		\
attr శూన్య name##_RB_REMOVE_COLOR(నిర్మాణం name *, నిర్మాణం type *, నిర్మాణం type *);\
attr నిర్మాణం type *name##_RB_REMOVE(నిర్మాణం name *, నిర్మాణం type *);	\
attr నిర్మాణం type *name##_RB_INSERT(నిర్మాణం name *, నిర్మాణం type *);	\
attr నిర్మాణం type *name##_RB_FIND(నిర్మాణం name *, నిర్మాణం type *);		\
attr నిర్మాణం type *name##_RB_NFIND(నిర్మాణం name *, నిర్మాణం type *);	\
attr నిర్మాణం type *name##_RB_NEXT(నిర్మాణం type *);			\
attr నిర్మాణం type *name##_RB_PREV(నిర్మాణం type *);			\
attr నిర్మాణం type *name##_RB_MINMAX(నిర్మాణం name *, పూర్ణాంకం);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#నిర్వచించు	RB_GENERATE(name, type, క్షేత్రం, cmp)				\
	RB_GENERATE_అంతర్గత(name, type, క్షేత్రం, cmp,)
#నిర్వచించు	RB_GENERATE_STATIC(name, type, క్షేత్రం, cmp)			\
	RB_GENERATE_అంతర్గత(name, type, క్షేత్రం, cmp, __attribute__((__unused__)) స్థిర)
#నిర్వచించు RB_GENERATE_అంతర్గత(name, type, క్షేత్రం, cmp, attr)		\
attr శూన్య								\
name##_RB_INSERT_COLOR(నిర్మాణం name *తల, నిర్మాణం type *elm)		\
{									\
	నిర్మాణం type *మాతృ, *gparent, *tmp;				\
	అయితే ((మాతృ = RB_మాతృ(elm, క్షేత్రం)) &&			\
	    RB_COLOR(మాతృ, క్షేత్రం) == RB_RED) {			\
		gparent = RB_మాతృ(మాతృ, క్షేత్రం);			\
		ఒకవేళ (మాతృ == RB_ఎడమ(gparent, క్షేత్రం)) {		\
			tmp = RB_కుడి(gparent, క్షేత్రం);			\
			ఒకవేళ (tmp && RB_COLOR(tmp, క్షేత్రం) == RB_RED) {	\
				RB_COLOR(tmp, క్షేత్రం) = RB_BLACK;	\
				RB_సమితి_BLACKRED(మాతృ, gparent, క్షేత్రం);\
				elm = gparent;				\
				కొనసాగు;				\
			}						\
			ఒకవేళ (RB_కుడి(మాతృ, క్షేత్రం) == elm) {		\
				RB_ROTATE_ఎడమ(తల, మాతృ, tmp, క్షేత్రం);\
				tmp = మాతృ;				\
				మాతృ = elm;				\
				elm = tmp;				\
			}						\
			RB_సమితి_BLACKRED(మాతృ, gparent, క్షేత్రం);	\
			RB_ROTATE_కుడి(తల, gparent, tmp, క్షేత్రం);	\
		} లేకపోతే {						\
			tmp = RB_ఎడమ(gparent, క్షేత్రం);			\
			ఒకవేళ (tmp && RB_COLOR(tmp, క్షేత్రం) == RB_RED) {	\
				RB_COLOR(tmp, క్షేత్రం) = RB_BLACK;	\
				RB_సమితి_BLACKRED(మాతృ, gparent, క్షేత్రం);\
				elm = gparent;				\
				కొనసాగు;				\
			}						\
			ఒకవేళ (RB_ఎడమ(మాతృ, క్షేత్రం) == elm) {		\
				RB_ROTATE_కుడి(తల, మాతృ, tmp, క్షేత్రం);\
				tmp = మాతృ;				\
				మాతృ = elm;				\
				elm = tmp;				\
			}						\
			RB_సమితి_BLACKRED(మాతృ, gparent, క్షేత్రం);	\
			RB_ROTATE_ఎడమ(తల, gparent, tmp, క్షేత్రం);	\
		}							\
	}								\
	RB_COLOR(తల->rbh_మూలం, క్షేత్రం) = RB_BLACK;			\
}									\
									\
attr శూన్య								\
name##_RB_REMOVE_COLOR(నిర్మాణం name *తల, నిర్మాణం type *మాతృ, నిర్మాణం type *elm) \
{									\
	నిర్మాణం type *tmp;						\
	అయితే ((elm == ఖాళీ || RB_COLOR(elm, క్షేత్రం) == RB_BLACK) &&	\
	    elm != RB_మూలం(తల)) {					\
		ఒకవేళ (RB_ఎడమ(మాతృ, క్షేత్రం) == elm) {			\
			tmp = RB_కుడి(మాతృ, క్షేత్రం);			\
			ఒకవేళ (RB_COLOR(tmp, క్షేత్రం) == RB_RED) {		\
				RB_సమితి_BLACKRED(tmp, మాతృ, క్షేత్రం);	\
				RB_ROTATE_ఎడమ(తల, మాతృ, tmp, క్షేత్రం);\
				tmp = RB_కుడి(మాతృ, క్షేత్రం);		\
			}						\
			ఒకవేళ ((RB_ఎడమ(tmp, క్షేత్రం) == ఖాళీ ||		\
			    RB_COLOR(RB_ఎడమ(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK) &&\
			    (RB_కుడి(tmp, క్షేత్రం) == ఖాళీ ||		\
			    RB_COLOR(RB_కుడి(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK)) {\
				RB_COLOR(tmp, క్షేత్రం) = RB_RED;		\
				elm = మాతృ;				\
				మాతృ = RB_మాతృ(elm, క్షేత్రం);		\
			} లేకపోతే {					\
				ఒకవేళ (RB_కుడి(tmp, క్షేత్రం) == ఖాళీ ||	\
				    RB_COLOR(RB_కుడి(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK) {\
					నిర్మాణం type *oleft;		\
					ఒకవేళ ((oleft = RB_ఎడమ(tmp, క్షేత్రం)))\
						RB_COLOR(oleft, క్షేత్రం) = RB_BLACK;\
					RB_COLOR(tmp, క్షేత్రం) = RB_RED;	\
					RB_ROTATE_కుడి(తల, tmp, oleft, క్షేత్రం);\
					tmp = RB_కుడి(మాతృ, క్షేత్రం);	\
				}					\
				RB_COLOR(tmp, క్షేత్రం) = RB_COLOR(మాతృ, క్షేత్రం);\
				RB_COLOR(మాతృ, క్షేత్రం) = RB_BLACK;	\
				ఒకవేళ (RB_కుడి(tmp, క్షేత్రం))		\
					RB_COLOR(RB_కుడి(tmp, క్షేత్రం), క్షేత్రం) = RB_BLACK;\
				RB_ROTATE_ఎడమ(తల, మాతృ, tmp, క్షేత్రం);\
				elm = RB_మూలం(తల);			\
				ఆపు;					\
			}						\
		} లేకపోతే {						\
			tmp = RB_ఎడమ(మాతృ, క్షేత్రం);			\
			ఒకవేళ (RB_COLOR(tmp, క్షేత్రం) == RB_RED) {		\
				RB_సమితి_BLACKRED(tmp, మాతృ, క్షేత్రం);	\
				RB_ROTATE_కుడి(తల, మాతృ, tmp, క్షేత్రం);\
				tmp = RB_ఎడమ(మాతృ, క్షేత్రం);		\
			}						\
			ఒకవేళ ((RB_ఎడమ(tmp, క్షేత్రం) == ఖాళీ ||		\
			    RB_COLOR(RB_ఎడమ(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK) &&\
			    (RB_కుడి(tmp, క్షేత్రం) == ఖాళీ ||		\
			    RB_COLOR(RB_కుడి(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK)) {\
				RB_COLOR(tmp, క్షేత్రం) = RB_RED;		\
				elm = మాతృ;				\
				మాతృ = RB_మాతృ(elm, క్షేత్రం);		\
			} లేకపోతే {					\
				ఒకవేళ (RB_ఎడమ(tmp, క్షేత్రం) == ఖాళీ ||	\
				    RB_COLOR(RB_ఎడమ(tmp, క్షేత్రం), క్షేత్రం) == RB_BLACK) {\
					నిర్మాణం type *oright;		\
					ఒకవేళ ((oright = RB_కుడి(tmp, క్షేత్రం)))\
						RB_COLOR(oright, క్షేత్రం) = RB_BLACK;\
					RB_COLOR(tmp, క్షేత్రం) = RB_RED;	\
					RB_ROTATE_ఎడమ(తల, tmp, oright, క్షేత్రం);\
					tmp = RB_ఎడమ(మాతృ, క్షేత్రం);	\
				}					\
				RB_COLOR(tmp, క్షేత్రం) = RB_COLOR(మాతృ, క్షేత్రం);\
				RB_COLOR(మాతృ, క్షేత్రం) = RB_BLACK;	\
				ఒకవేళ (RB_ఎడమ(tmp, క్షేత్రం))		\
					RB_COLOR(RB_ఎడమ(tmp, క్షేత్రం), క్షేత్రం) = RB_BLACK;\
				RB_ROTATE_కుడి(తల, మాతృ, tmp, క్షేత్రం);\
				elm = RB_మూలం(తల);			\
				ఆపు;					\
			}						\
		}							\
	}								\
	ఒకవేళ (elm)							\
		RB_COLOR(elm, క్షేత్రం) = RB_BLACK;			\
}									\
									\
attr నిర్మాణం type *							\
name##_RB_REMOVE(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	నిర్మాణం type *బిడ్డ, *మాతృ, *old = elm;			\
	పూర్ణాంకం color;							\
	ఒకవేళ (RB_ఎడమ(elm, క్షేత్రం) == ఖాళీ)				\
		బిడ్డ = RB_కుడి(elm, క్షేత్రం);				\
	లేకపోతే ఒకవేళ (RB_కుడి(elm, క్షేత్రం) == ఖాళీ)				\
		బిడ్డ = RB_ఎడమ(elm, క్షేత్రం);				\
	లేకపోతే {								\
		నిర్మాణం type *ఎడమ;					\
		elm = RB_కుడి(elm, క్షేత్రం);				\
		అయితే ((ఎడమ = RB_ఎడమ(elm, క్షేత్రం)))			\
			elm = ఎడమ;					\
		బిడ్డ = RB_కుడి(elm, క్షేత్రం);				\
		మాతృ = RB_మాతృ(elm, క్షేత్రం);				\
		color = RB_COLOR(elm, క్షేత్రం);				\
		ఒకవేళ (బిడ్డ)						\
			RB_మాతృ(బిడ్డ, క్షేత్రం) = మాతృ;		\
		ఒకవేళ (మాతృ) {						\
			ఒకవేళ (RB_ఎడమ(మాతృ, క్షేత్రం) == elm)		\
				RB_ఎడమ(మాతృ, క్షేత్రం) = బిడ్డ;		\
			లేకపోతే						\
				RB_కుడి(మాతృ, క్షేత్రం) = బిడ్డ;	\
			RB_AUGMENT(మాతృ);				\
		} లేకపోతే							\
			RB_మూలం(తల) = బిడ్డ;				\
		ఒకవేళ (RB_మాతృ(elm, క్షేత్రం) == old)			\
			మాతృ = elm;					\
		(elm)->క్షేత్రం = (old)->క్షేత్రం;				\
		ఒకవేళ (RB_మాతృ(old, క్షేత్రం)) {				\
			ఒకవేళ (RB_ఎడమ(RB_మాతృ(old, క్షేత్రం), క్షేత్రం) == old)\
				RB_ఎడమ(RB_మాతృ(old, క్షేత్రం), క్షేత్రం) = elm;\
			లేకపోతే						\
				RB_కుడి(RB_మాతృ(old, క్షేత్రం), క్షేత్రం) = elm;\
			RB_AUGMENT(RB_మాతృ(old, క్షేత్రం));		\
		} లేకపోతే							\
			RB_మూలం(తల) = elm;				\
		RB_మాతృ(RB_ఎడమ(old, క్షేత్రం), క్షేత్రం) = elm;		\
		ఒకవేళ (RB_కుడి(old, క్షేత్రం))				\
			RB_మాతృ(RB_కుడి(old, క్షేత్రం), క్షేత్రం) = elm;	\
		ఒకవేళ (మాతృ) {						\
			ఎడమ = మాతృ;					\
			చేయి {						\
				RB_AUGMENT(ఎడమ);			\
			} అయితే ((ఎడమ = RB_మాతృ(ఎడమ, క్షేత్రం)));	\
		}							\
		వెళ్ళు color;						\
	}								\
	మాతృ = RB_మాతృ(elm, క్షేత్రం);					\
	color = RB_COLOR(elm, క్షేత్రం);					\
	ఒకవేళ (బిడ్డ)							\
		RB_మాతృ(బిడ్డ, క్షేత్రం) = మాతృ;			\
	ఒకవేళ (మాతృ) {							\
		ఒకవేళ (RB_ఎడమ(మాతృ, క్షేత్రం) == elm)			\
			RB_ఎడమ(మాతృ, క్షేత్రం) = బిడ్డ;			\
		లేకపోతే							\
			RB_కుడి(మాతృ, క్షేత్రం) = బిడ్డ;		\
		RB_AUGMENT(మాతృ);					\
	} లేకపోతే								\
		RB_మూలం(తల) = బిడ్డ;					\
color:									\
	ఒకవేళ (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(తల, మాతృ, బిడ్డ);		\
	తిరిగి (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr నిర్మాణం type *							\
name##_RB_INSERT(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	నిర్మాణం type *tmp;						\
	నిర్మాణం type *మాతృ = ఖాళీ;					\
	పూర్ణాంకం comp = 0;							\
	tmp = RB_మూలం(తల);						\
	అయితే (tmp) {							\
		మాతృ = tmp;						\
		comp = (cmp)(elm, మాతృ);				\
		ఒకవేళ (comp < 0)						\
			tmp = RB_ఎడమ(tmp, క్షేత్రం);			\
		లేకపోతే ఒకవేళ (comp > 0)					\
			tmp = RB_కుడి(tmp, క్షేత్రం);			\
		లేకపోతే							\
			తిరిగి (tmp);					\
	}								\
	RB_సమితి(elm, మాతృ, క్షేత్రం);					\
	ఒకవేళ (మాతృ != ఖాళీ) {						\
		ఒకవేళ (comp < 0)						\
			RB_ఎడమ(మాతృ, క్షేత్రం) = elm;			\
		లేకపోతే							\
			RB_కుడి(మాతృ, క్షేత్రం) = elm;			\
		RB_AUGMENT(మాతృ);					\
	} లేకపోతే								\
		RB_మూలం(తల) = elm;					\
	name##_RB_INSERT_COLOR(తల, elm);				\
	తిరిగి (ఖాళీ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr నిర్మాణం type *							\
name##_RB_FIND(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	నిర్మాణం type *tmp = RB_మూలం(తల);				\
	పూర్ణాంకం comp;							\
	అయితే (tmp) {							\
		comp = cmp(elm, tmp);					\
		ఒకవేళ (comp < 0)						\
			tmp = RB_ఎడమ(tmp, క్షేత్రం);			\
		లేకపోతే ఒకవేళ (comp > 0)					\
			tmp = RB_కుడి(tmp, క్షేత్రం);			\
		లేకపోతే							\
			తిరిగి (tmp);					\
	}								\
	తిరిగి (ఖాళీ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr నిర్మాణం type *							\
name##_RB_NFIND(నిర్మాణం name *తల, నిర్మాణం type *elm)			\
{									\
	నిర్మాణం type *tmp = RB_మూలం(తల);				\
	నిర్మాణం type *res = ఖాళీ;					\
	పూర్ణాంకం comp;							\
	అయితే (tmp) {							\
		comp = cmp(elm, tmp);					\
		ఒకవేళ (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ఎడమ(tmp, క్షేత్రం);			\
		}							\
		లేకపోతే ఒకవేళ (comp > 0)					\
			tmp = RB_కుడి(tmp, క్షేత్రం);			\
		లేకపోతే							\
			తిరిగి (tmp);					\
	}								\
	తిరిగి (res);							\
}									\
									\
/* ARGSUSED */								\
attr నిర్మాణం type *							\
name##_RB_NEXT(నిర్మాణం type *elm)					\
{									\
	ఒకవేళ (RB_కుడి(elm, క్షేత్రం)) {					\
		elm = RB_కుడి(elm, క్షేత్రం);				\
		అయితే (RB_ఎడమ(elm, క్షేత్రం))				\
			elm = RB_ఎడమ(elm, క్షేత్రం);			\
	} లేకపోతే {							\
		ఒకవేళ (RB_మాతృ(elm, క్షేత్రం) &&				\
		    (elm == RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం)))	\
			elm = RB_మాతృ(elm, క్షేత్రం);			\
		లేకపోతే {							\
			అయితే (RB_మాతృ(elm, క్షేత్రం) &&			\
			    (elm == RB_కుడి(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం)))\
				elm = RB_మాతృ(elm, క్షేత్రం);		\
			elm = RB_మాతృ(elm, క్షేత్రం);			\
		}							\
	}								\
	తిరిగి (elm);							\
}									\
									\
/* ARGSUSED */								\
attr నిర్మాణం type *							\
name##_RB_PREV(నిర్మాణం type *elm)					\
{									\
	ఒకవేళ (RB_ఎడమ(elm, క్షేత్రం)) {					\
		elm = RB_ఎడమ(elm, క్షేత్రం);				\
		అయితే (RB_కుడి(elm, క్షేత్రం))				\
			elm = RB_కుడి(elm, క్షేత్రం);			\
	} లేకపోతే {							\
		ఒకవేళ (RB_మాతృ(elm, క్షేత్రం) &&				\
		    (elm == RB_కుడి(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం)))	\
			elm = RB_మాతృ(elm, క్షేత్రం);			\
		లేకపోతే {							\
			అయితే (RB_మాతృ(elm, క్షేత్రం) &&			\
			    (elm == RB_ఎడమ(RB_మాతృ(elm, క్షేత్రం), క్షేత్రం)))\
				elm = RB_మాతృ(elm, క్షేత్రం);		\
			elm = RB_మాతృ(elm, క్షేత్రం);			\
		}							\
	}								\
	తిరిగి (elm);							\
}									\
									\
attr నిర్మాణం type *							\
name##_RB_MINMAX(నిర్మాణం name *తల, పూర్ణాంకం val)				\
{									\
	నిర్మాణం type *tmp = RB_మూలం(తల);				\
	నిర్మాణం type *మాతృ = ఖాళీ;					\
	అయితే (tmp) {							\
		మాతృ = tmp;						\
		ఒకవేళ (val < 0)						\
			tmp = RB_ఎడమ(tmp, క్షేత్రం);			\
		లేకపోతే							\
			tmp = RB_కుడి(tmp, క్షేత్రం);			\
	}								\
	తిరిగి (మాతృ);						\
}

#నిర్వచించు RB_NEGINF	-1
#నిర్వచించు RB_INF	1

#నిర్వచించు RB_చొప్పించు(name, x, y)	name##_RB_INSERT(x, y)
#నిర్వచించు RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#నిర్వచించు RB_కనుగొను(name, x, y)	name##_RB_FIND(x, y)
#నిర్వచించు RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#నిర్వచించు RB_తదుపరి(name, x, y)	name##_RB_NEXT(y)
#నిర్వచించు RB_PREV(name, x, y)	name##_RB_PREV(y)
#నిర్వచించు RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#నిర్వచించు RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#నిర్వచించు RB_FOREACH(x, name, తల)					\
	కొరకు ((x) = RB_MIN(name, తల);					\
	     (x) != ఖాళీ;						\
	     (x) = name##_RB_NEXT(x))

#నిర్వచించు RB_FOREACH_సురక్షిత(x, name, తల, y)				\
	కొరకు ((x) = RB_MIN(name, తల);					\
	    ((x) != ఖాళీ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#నిర్వచించు RB_FOREACH_తిరగేయి(x, name, తల)				\
	కొరకు ((x) = RB_MAX(name, తల);					\
	     (x) != ఖాళీ;						\
	     (x) = name##_RB_PREV(x))

#నిర్వచించు RB_FOREACH_తిరగేయి_సురక్షిత(x, name, తల, y)			\
	కొరకు ((x) = RB_MAX(name, తల);					\
	    ((x) != ఖాళీ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#అయితే_ముగింపు	/* _SYS_TREE_H_ */
