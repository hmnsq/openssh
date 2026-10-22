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

#ಅನ್ತರ್ಭಾವ "config.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ	SYS_ವೃಕ್ಷ_H
#ವ್ಯಾಖ್ಯಾನಿಸು	SYS_ವೃಕ್ಷ_H

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

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ತಲೆ(name, type)						\
ರಚನೆ name {								\
	ರಚನೆ type *sph_ಬೇರು; /* root of the tree */			\
}

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_INITIALIZER(ಬೇರು)						\
	{ ಖಾಲಿ }

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_INIT(ಬೇರು) ಮಾಡು {						\
	(ಬೇರು)->sph_ಬೇರು = ಖಾಲಿ;					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ನಮೂದು(type)						\
ರಚನೆ {								\
	ರಚನೆ type *spe_ಎಡ; /* left element */			\
	ರಚನೆ type *spe_ಬಲ; /* right element */			\
}

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.spe_ಎಡ
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.spe_ಬಲ
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಬೇರು(ತಲೆ)		(ತಲೆ)->sph_ಬೇರು
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಖಾಲಿಗಳು(ತಲೆ)		(SPLAY_ಬೇರು(ತಲೆ) == ಖಾಲಿ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ROTATE_ಬಲ(ತಲೆ, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ(tmp, ಕ್ಷೇತ್ರ);	\
	SPLAY_ಬಲ(tmp, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;			\
	(ತಲೆ)->sph_ಬೇರು = tmp;						\
} ಆಗ (0)
	
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ROTATE_ಎಡ(ತಲೆ, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = SPLAY_ಎಡ(tmp, ಕ್ಷೇತ್ರ);	\
	SPLAY_ಎಡ(tmp, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;			\
	(ತಲೆ)->sph_ಬೇರು = tmp;						\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_LINKLEFT(ತಲೆ, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	SPLAY_ಎಡ(tmp, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;			\
	tmp = (ತಲೆ)->sph_ಬೇರು;						\
	(ತಲೆ)->sph_ಬೇರು = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);		\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_LINKRIGHT(ತಲೆ, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	SPLAY_ಬಲ(tmp, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;			\
	tmp = (ತಲೆ)->sph_ಬೇರು;						\
	(ತಲೆ)->sph_ಬೇರು = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ASSEMBLE(ತಲೆ, ಗಂಟು, ಎಡ, ಬಲ, ಕ್ಷೇತ್ರ) ಮಾಡು {		\
	SPLAY_ಬಲ(ಎಡ, ಕ್ಷೇತ್ರ) = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
	SPLAY_ಎಡ(ಬಲ, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);\
	SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ(ಗಂಟು, ಕ್ಷೇತ್ರ);	\
	SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = SPLAY_ಎಡ(ಗಂಟು, ಕ್ಷೇತ್ರ);	\
} ಆಗ (0)

/* Generates prototypes and inline functions */

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_PROTOTYPE(name, type, ಕ್ಷೇತ್ರ, cmp)				\
ಶೂನ್ಯ name##_SPLAY(ರಚನೆ name *, ರಚನೆ type *);			\
ಶೂನ್ಯ name##_SPLAY_MINMAX(ರಚನೆ name *, ಪೂರ್ಣಾಂಕ);				\
ರಚನೆ type *name##_SPLAY_INSERT(ರಚನೆ name *, ರಚನೆ type *);		\
ರಚನೆ type *name##_SPLAY_REMOVE(ರಚನೆ name *, ರಚನೆ type *);		\
									\
/* Finds the node with the same key as elm */				\
ಸ್ಥಿರ __inline ರಚನೆ type *						\
name##_SPLAY_FIND(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ಆದರೆ (SPLAY_ಖಾಲಿಗಳು(ತಲೆ))						\
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);						\
	name##_SPLAY(ತಲೆ, elm);					\
	ಆದರೆ ((cmp)(elm, (ತಲೆ)->sph_ಬೇರು) == 0)				\
		ಹಿಂತಿರುಗಿ (ತಲೆ->sph_ಬೇರು);				\
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);							\
}									\
									\
ಸ್ಥಿರ __inline ರಚನೆ type *						\
name##_SPLAY_NEXT(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	name##_SPLAY(ತಲೆ, elm);					\
	ಆದರೆ (SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ) != ಖಾಲಿ) {				\
		elm = SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ);				\
		ಆಗ (SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ) != ಖಾಲಿ) {		\
			elm = SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ);			\
		}							\
	} ಇಲ್ಲದಿದ್ದರೆ								\
		elm = ಖಾಲಿ;						\
	ಹಿಂತಿರುಗಿ (elm);							\
}									\
									\
ಸ್ಥಿರ __inline ರಚನೆ type *						\
name##_SPLAY_MIN_MAX(ರಚನೆ name *ತಲೆ, ಪೂರ್ಣಾಂಕ val)			\
{									\
	name##_SPLAY_MINMAX(ತಲೆ, val);					\
        ಹಿಂತಿರುಗಿ (SPLAY_ಬೇರು(ತಲೆ));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_GENERATE(name, type, ಕ್ಷೇತ್ರ, cmp)				\
ರಚನೆ type *								\
name##_SPLAY_INSERT(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)		\
{									\
    ಆದರೆ (SPLAY_ಖಾಲಿಗಳು(ತಲೆ)) {						\
	    SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;	\
    } ಇಲ್ಲದಿದ್ದರೆ {								\
	    ಪೂರ್ಣಾಂಕ __comp;							\
	    name##_SPLAY(ತಲೆ, elm);					\
	    __comp = (cmp)(elm, (ತಲೆ)->sph_ಬೇರು);			\
	    ಆದರೆ(__comp < 0) {						\
		    SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ) = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);\
		    SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;		\
		    SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;		\
	    } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (__comp > 0) {					\
		    SPLAY_ಬಲ(elm, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);\
		    SPLAY_ಎಡ(elm, ಕ್ಷೇತ್ರ) = (ತಲೆ)->sph_ಬೇರು;		\
		    SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;	\
	    } ಇಲ್ಲದಿದ್ದರೆ							\
		    ಹಿಂತಿರುಗಿ ((ತಲೆ)->sph_ಬೇರು);				\
    }									\
    (ತಲೆ)->sph_ಬೇರು = (elm);						\
    ಹಿಂತಿರುಗಿ (ಖಾಲಿ);							\
}									\
									\
ರಚನೆ type *								\
name##_SPLAY_REMOVE(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)		\
{									\
	ರಚನೆ type *__tmp;						\
	ಆದರೆ (SPLAY_ಖಾಲಿಗಳು(ತಲೆ))						\
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);						\
	name##_SPLAY(ತಲೆ, elm);					\
	ಆದರೆ ((cmp)(elm, (ತಲೆ)->sph_ಬೇರು) == 0) {			\
		ಆದರೆ (SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) == ಖಾಲಿ) {	\
			(ತಲೆ)->sph_ಬೇರು = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);\
		} ಇಲ್ಲದಿದ್ದರೆ {						\
			__tmp = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
			(ತಲೆ)->sph_ಬೇರು = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);\
			name##_SPLAY(ತಲೆ, elm);			\
			SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) = __tmp;	\
		}							\
		ಹಿಂತಿರುಗಿ (elm);						\
	}								\
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);							\
}									\
									\
ಶೂನ್ಯ									\
name##_SPLAY(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ರಚನೆ type __node, *__left, *__right, *__tmp;			\
	ಪೂರ್ಣಾಂಕ __comp;							\
\
	SPLAY_ಎಡ(&__node, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ(&__node, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;\
	__left = __right = &__node;					\
\
	ಆಗ ((__comp = (cmp)(elm, (ತಲೆ)->sph_ಬೇರು))) {		\
		ಆದರೆ (__comp < 0) {					\
			__tmp = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
			ಆದರೆ (__tmp == ಖಾಲಿ)				\
				ನಿಲ್ಲಿಸು;					\
			ಆದರೆ ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ಬಲ(ತಲೆ, __tmp, ಕ್ಷೇತ್ರ);	\
				ಆದರೆ (SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)\
					ನಿಲ್ಲಿಸು;				\
			}						\
			SPLAY_LINKLEFT(ತಲೆ, __right, ಕ್ಷೇತ್ರ);		\
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (__comp > 0) {				\
			__tmp = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
			ಆದರೆ (__tmp == ಖಾಲಿ)				\
				ನಿಲ್ಲಿಸು;					\
			ಆದರೆ ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ಎಡ(ತಲೆ, __tmp, ಕ್ಷೇತ್ರ);	\
				ಆದರೆ (SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)\
					ನಿಲ್ಲಿಸು;				\
			}						\
			SPLAY_LINKRIGHT(ತಲೆ, __left, ಕ್ಷೇತ್ರ);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(ತಲೆ, &__node, __left, __right, ಕ್ಷೇತ್ರ);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
ಶೂನ್ಯ name##_SPLAY_MINMAX(ರಚನೆ name *ತಲೆ, ಪೂರ್ಣಾಂಕ __comp) \
{									\
	ರಚನೆ type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ಎಡ(&__node, ಕ್ಷೇತ್ರ) = SPLAY_ಬಲ(&__node, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;\
	__left = __right = &__node;					\
\
	ಆಗ (1) {							\
		ಆದರೆ (__comp < 0) {					\
			__tmp = SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
			ಆದರೆ (__tmp == ಖಾಲಿ)				\
				ನಿಲ್ಲಿಸು;					\
			ಆದರೆ (__comp < 0){				\
				SPLAY_ROTATE_ಬಲ(ತಲೆ, __tmp, ಕ್ಷೇತ್ರ);	\
				ಆದರೆ (SPLAY_ಎಡ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)\
					ನಿಲ್ಲಿಸು;				\
			}						\
			SPLAY_LINKLEFT(ತಲೆ, __right, ಕ್ಷೇತ್ರ);		\
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (__comp > 0) {				\
			__tmp = SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ);	\
			ಆದರೆ (__tmp == ಖಾಲಿ)				\
				ನಿಲ್ಲಿಸು;					\
			ಆದರೆ (__comp > 0) {				\
				SPLAY_ROTATE_ಎಡ(ತಲೆ, __tmp, ಕ್ಷೇತ್ರ);	\
				ಆದರೆ (SPLAY_ಬಲ((ತಲೆ)->sph_ಬೇರು, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)\
					ನಿಲ್ಲಿಸು;				\
			}						\
			SPLAY_LINKRIGHT(ತಲೆ, __left, ಕ್ಷೇತ್ರ);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(ತಲೆ, &__node, __left, __right, ಕ್ಷೇತ್ರ);		\
}

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_NEGINF	-1
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_INF	1

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಸೇರಿಸು(name, x, y)	name##_SPLAY_INSERT(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಕಂಡುಹಿಡಿ(name, x, y)		name##_SPLAY_FIND(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_ಮುಂದಿನ(name, x, y)		name##_SPLAY_NEXT(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_MIN(name, x)		(SPLAY_ಖಾಲಿಗಳು(x) ? ಖಾಲಿ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_MAX(name, x)		(SPLAY_ಖಾಲಿಗಳು(x) ? ಖಾಲಿ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#ವ್ಯಾಖ್ಯಾನಿಸು SPLAY_FOREACH(x, name, ತಲೆ)					\
	ಗಾಗಿ ((x) = SPLAY_MIN(name, ತಲೆ);				\
	     (x) != ಖಾಲಿ;						\
	     (x) = SPLAY_ಮುಂದಿನ(name, ತಲೆ, x))

/* Macros that define a red-black tree */
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ತಲೆ(name, type)						\
ರಚನೆ name {								\
	ರಚನೆ type *rbh_ಬೇರು; /* root of the tree */			\
}

#ವ್ಯಾಖ್ಯಾನಿಸು RB_INITIALIZER(ಬೇರು)						\
	{ ಖಾಲಿ }

#ವ್ಯಾಖ್ಯಾನಿಸು RB_INIT(ಬೇರು) ಮಾಡು {						\
	(ಬೇರು)->rbh_ಬೇರು = ಖಾಲಿ;					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು RB_BLACK	0
#ವ್ಯಾಖ್ಯಾನಿಸು RB_RED		1
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ನಮೂದು(type)							\
ರಚನೆ {								\
	ರಚನೆ type *rbe_ಎಡ;		/* left element */		\
	ರಚನೆ type *rbe_ಬಲ;		/* right element */		\
	ರಚನೆ type *rbe_ಪೋಷಕ;	/* parent element */		\
	ಪೂರ್ಣಾಂಕ rbe_color;			/* node color */		\
}

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಎಡ(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.rbe_ಎಡ
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಬಲ(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.rbe_ಬಲ
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.rbe_ಪೋಷಕ
#ವ್ಯಾಖ್ಯಾನಿಸು RB_COLOR(elm, ಕ್ಷೇತ್ರ)		(elm)->ಕ್ಷೇತ್ರ.rbe_color
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಬೇರು(ತಲೆ)			(ತಲೆ)->rbh_ಬೇರು
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಖಾಲಿಗಳು(ತಲೆ)			(RB_ಬೇರು(ತಲೆ) == ಖಾಲಿ)

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಗಣ(elm, ಪೋಷಕ, ಕ್ಷೇತ್ರ) ಮಾಡು {					\
	RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) = ಪೋಷಕ;					\
	RB_ಎಡ(elm, ಕ್ಷೇತ್ರ) = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ) = ಖಾಲಿ;		\
	RB_COLOR(elm, ಕ್ಷೇತ್ರ) = RB_RED;					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಗಣ_BLACKRED(black, red, ಕ್ಷೇತ್ರ) ಮಾಡು {				\
	RB_COLOR(black, ಕ್ಷೇತ್ರ) = RB_BLACK;				\
	RB_COLOR(red, ಕ್ಷೇತ್ರ) = RB_RED;					\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ RB_AUGMENT
#ವ್ಯಾಖ್ಯಾನಿಸು RB_AUGMENT(x)	ಮಾಡು {} ಆಗ (0)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ROTATE_ಎಡ(ತಲೆ, elm, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(tmp) = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);					\
	ಆದರೆ ((RB_ಬಲ(elm, ಕ್ಷೇತ್ರ) = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ))) {		\
		RB_ಪೋಷಕ(RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ಆದರೆ ((RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ) = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ))) {		\
		ಆದರೆ ((elm) == RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ))	\
			RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (tmp);	\
		ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬಲ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (tmp);	\
	} ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->rbh_ಬೇರು = (tmp);				\
	RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ) = (elm);					\
	RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ಆದರೆ ((RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ)))					\
		RB_AUGMENT(RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ));			\
} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ROTATE_ಬಲ(ತಲೆ, elm, tmp, ಕ್ಷೇತ್ರ) ಮಾಡು {			\
	(tmp) = RB_ಎಡ(elm, ಕ್ಷೇತ್ರ);					\
	ಆದರೆ ((RB_ಎಡ(elm, ಕ್ಷೇತ್ರ) = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ))) {		\
		RB_ಪೋಷಕ(RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ಆದರೆ ((RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ) = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ))) {		\
		ಆದರೆ ((elm) == RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ))	\
			RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (tmp);	\
		ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬಲ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = (tmp);	\
	} ಇಲ್ಲದಿದ್ದರೆ								\
		(ತಲೆ)->rbh_ಬೇರು = (tmp);				\
	RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ) = (elm);					\
	RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ಆದರೆ ((RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ)))					\
		RB_AUGMENT(RB_ಪೋಷಕ(tmp, ಕ್ಷೇತ್ರ));			\
} ಆಗ (0)

/* Generates prototypes and inline functions */
#ವ್ಯಾಖ್ಯಾನಿಸು	RB_PROTOTYPE(name, type, ಕ್ಷೇತ್ರ, cmp)				\
	RB_PROTOTYPE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp,)
#ವ್ಯಾಖ್ಯಾನಿಸು	RB_PROTOTYPE_STATIC(name, type, ಕ್ಷೇತ್ರ, cmp)			\
	RB_PROTOTYPE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp, __attribute__((__unused__)) ಸ್ಥಿರ)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_PROTOTYPE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp, attr)		\
attr ಶೂನ್ಯ name##_RB_INSERT_COLOR(ರಚನೆ name *, ರಚನೆ type *);		\
attr ಶೂನ್ಯ name##_RB_REMOVE_COLOR(ರಚನೆ name *, ರಚನೆ type *, ರಚನೆ type *);\
attr ರಚನೆ type *name##_RB_REMOVE(ರಚನೆ name *, ರಚನೆ type *);	\
attr ರಚನೆ type *name##_RB_INSERT(ರಚನೆ name *, ರಚನೆ type *);	\
attr ರಚನೆ type *name##_RB_FIND(ರಚನೆ name *, ರಚನೆ type *);		\
attr ರಚನೆ type *name##_RB_NFIND(ರಚನೆ name *, ರಚನೆ type *);	\
attr ರಚನೆ type *name##_RB_NEXT(ರಚನೆ type *);			\
attr ರಚನೆ type *name##_RB_PREV(ರಚನೆ type *);			\
attr ರಚನೆ type *name##_RB_MINMAX(ರಚನೆ name *, ಪೂರ್ಣಾಂಕ);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	RB_GENERATE(name, type, ಕ್ಷೇತ್ರ, cmp)				\
	RB_GENERATE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp,)
#ವ್ಯಾಖ್ಯಾನಿಸು	RB_GENERATE_STATIC(name, type, ಕ್ಷೇತ್ರ, cmp)			\
	RB_GENERATE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp, __attribute__((__unused__)) ಸ್ಥಿರ)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_GENERATE_ಆಂತರಿಕ(name, type, ಕ್ಷೇತ್ರ, cmp, attr)		\
attr ಶೂನ್ಯ								\
name##_RB_INSERT_COLOR(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)		\
{									\
	ರಚನೆ type *ಪೋಷಕ, *gparent, *tmp;				\
	ಆಗ ((ಪೋಷಕ = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ)) &&			\
	    RB_COLOR(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == RB_RED) {			\
		gparent = RB_ಪೋಷಕ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);			\
		ಆದರೆ (ಪೋಷಕ == RB_ಎಡ(gparent, ಕ್ಷೇತ್ರ)) {		\
			tmp = RB_ಬಲ(gparent, ಕ್ಷೇತ್ರ);			\
			ಆದರೆ (tmp && RB_COLOR(tmp, ಕ್ಷೇತ್ರ) == RB_RED) {	\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_BLACK;	\
				RB_ಗಣ_BLACKRED(ಪೋಷಕ, gparent, ಕ್ಷೇತ್ರ);\
				elm = gparent;				\
				ಮುಂದುವರಿ;				\
			}						\
			ಆದರೆ (RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == elm) {		\
				RB_ROTATE_ಎಡ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				tmp = ಪೋಷಕ;				\
				ಪೋಷಕ = elm;				\
				elm = tmp;				\
			}						\
			RB_ಗಣ_BLACKRED(ಪೋಷಕ, gparent, ಕ್ಷೇತ್ರ);	\
			RB_ROTATE_ಬಲ(ತಲೆ, gparent, tmp, ಕ್ಷೇತ್ರ);	\
		} ಇಲ್ಲದಿದ್ದರೆ {						\
			tmp = RB_ಎಡ(gparent, ಕ್ಷೇತ್ರ);			\
			ಆದರೆ (tmp && RB_COLOR(tmp, ಕ್ಷೇತ್ರ) == RB_RED) {	\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_BLACK;	\
				RB_ಗಣ_BLACKRED(ಪೋಷಕ, gparent, ಕ್ಷೇತ್ರ);\
				elm = gparent;				\
				ಮುಂದುವರಿ;				\
			}						\
			ಆದರೆ (RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == elm) {		\
				RB_ROTATE_ಬಲ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				tmp = ಪೋಷಕ;				\
				ಪೋಷಕ = elm;				\
				elm = tmp;				\
			}						\
			RB_ಗಣ_BLACKRED(ಪೋಷಕ, gparent, ಕ್ಷೇತ್ರ);	\
			RB_ROTATE_ಎಡ(ತಲೆ, gparent, tmp, ಕ್ಷೇತ್ರ);	\
		}							\
	}								\
	RB_COLOR(ತಲೆ->rbh_ಬೇರು, ಕ್ಷೇತ್ರ) = RB_BLACK;			\
}									\
									\
attr ಶೂನ್ಯ								\
name##_RB_REMOVE_COLOR(ರಚನೆ name *ತಲೆ, ರಚನೆ type *ಪೋಷಕ, ರಚನೆ type *elm) \
{									\
	ರಚನೆ type *tmp;						\
	ಆಗ ((elm == ಖಾಲಿ || RB_COLOR(elm, ಕ್ಷೇತ್ರ) == RB_BLACK) &&	\
	    elm != RB_ಬೇರು(ತಲೆ)) {					\
		ಆದರೆ (RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == elm) {			\
			tmp = RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);			\
			ಆದರೆ (RB_COLOR(tmp, ಕ್ಷೇತ್ರ) == RB_RED) {		\
				RB_ಗಣ_BLACKRED(tmp, ಪೋಷಕ, ಕ್ಷೇತ್ರ);	\
				RB_ROTATE_ಎಡ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				tmp = RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);		\
			}						\
			ಆದರೆ ((RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||		\
			    RB_COLOR(RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK) &&\
			    (RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||		\
			    RB_COLOR(RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK)) {\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_RED;		\
				elm = ಪೋಷಕ;				\
				ಪೋಷಕ = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);		\
			} ಇಲ್ಲದಿದ್ದರೆ {					\
				ಆದರೆ (RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||	\
				    RB_COLOR(RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK) {\
					ರಚನೆ type *oleft;		\
					ಆದರೆ ((oleft = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ)))\
						RB_COLOR(oleft, ಕ್ಷೇತ್ರ) = RB_BLACK;\
					RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_RED;	\
					RB_ROTATE_ಬಲ(ತಲೆ, tmp, oleft, ಕ್ಷೇತ್ರ);\
					tmp = RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);	\
				}					\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_COLOR(ಪೋಷಕ, ಕ್ಷೇತ್ರ);\
				RB_COLOR(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = RB_BLACK;	\
				ಆದರೆ (RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ))		\
					RB_COLOR(RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = RB_BLACK;\
				RB_ROTATE_ಎಡ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				elm = RB_ಬೇರು(ತಲೆ);			\
				ನಿಲ್ಲಿಸು;					\
			}						\
		} ಇಲ್ಲದಿದ್ದರೆ {						\
			tmp = RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);			\
			ಆದರೆ (RB_COLOR(tmp, ಕ್ಷೇತ್ರ) == RB_RED) {		\
				RB_ಗಣ_BLACKRED(tmp, ಪೋಷಕ, ಕ್ಷೇತ್ರ);	\
				RB_ROTATE_ಬಲ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				tmp = RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);		\
			}						\
			ಆದರೆ ((RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||		\
			    RB_COLOR(RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK) &&\
			    (RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||		\
			    RB_COLOR(RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK)) {\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_RED;		\
				elm = ಪೋಷಕ;				\
				ಪೋಷಕ = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);		\
			} ಇಲ್ಲದಿದ್ದರೆ {					\
				ಆದರೆ (RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ) == ಖಾಲಿ ||	\
				    RB_COLOR(RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == RB_BLACK) {\
					ರಚನೆ type *oright;		\
					ಆದರೆ ((oright = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ)))\
						RB_COLOR(oright, ಕ್ಷೇತ್ರ) = RB_BLACK;\
					RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_RED;	\
					RB_ROTATE_ಎಡ(ತಲೆ, tmp, oright, ಕ್ಷೇತ್ರ);\
					tmp = RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ);	\
				}					\
				RB_COLOR(tmp, ಕ್ಷೇತ್ರ) = RB_COLOR(ಪೋಷಕ, ಕ್ಷೇತ್ರ);\
				RB_COLOR(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = RB_BLACK;	\
				ಆದರೆ (RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ))		\
					RB_COLOR(RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = RB_BLACK;\
				RB_ROTATE_ಬಲ(ತಲೆ, ಪೋಷಕ, tmp, ಕ್ಷೇತ್ರ);\
				elm = RB_ಬೇರು(ತಲೆ);			\
				ನಿಲ್ಲಿಸು;					\
			}						\
		}							\
	}								\
	ಆದರೆ (elm)							\
		RB_COLOR(elm, ಕ್ಷೇತ್ರ) = RB_BLACK;			\
}									\
									\
attr ರಚನೆ type *							\
name##_RB_REMOVE(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ರಚನೆ type *ಮಗು, *ಪೋಷಕ, *old = elm;			\
	ಪೂರ್ಣಾಂಕ color;							\
	ಆದರೆ (RB_ಎಡ(elm, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)				\
		ಮಗು = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);				\
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (RB_ಬಲ(elm, ಕ್ಷೇತ್ರ) == ಖಾಲಿ)				\
		ಮಗು = RB_ಎಡ(elm, ಕ್ಷೇತ್ರ);				\
	ಇಲ್ಲದಿದ್ದರೆ {								\
		ರಚನೆ type *ಎಡ;					\
		elm = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);				\
		ಆಗ ((ಎಡ = RB_ಎಡ(elm, ಕ್ಷೇತ್ರ)))			\
			elm = ಎಡ;					\
		ಮಗು = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);				\
		ಪೋಷಕ = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);				\
		color = RB_COLOR(elm, ಕ್ಷೇತ್ರ);				\
		ಆದರೆ (ಮಗು)						\
			RB_ಪೋಷಕ(ಮಗು, ಕ್ಷೇತ್ರ) = ಪೋಷಕ;		\
		ಆದರೆ (ಪೋಷಕ) {						\
			ಆದರೆ (RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == elm)		\
				RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = ಮಗು;		\
			ಇಲ್ಲದಿದ್ದರೆ						\
				RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = ಮಗು;	\
			RB_AUGMENT(ಪೋಷಕ);				\
		} ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬೇರು(ತಲೆ) = ಮಗು;				\
		ಆದರೆ (RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) == old)			\
			ಪೋಷಕ = elm;					\
		(elm)->ಕ್ಷೇತ್ರ = (old)->ಕ್ಷೇತ್ರ;				\
		ಆದರೆ (RB_ಪೋಷಕ(old, ಕ್ಷೇತ್ರ)) {				\
			ಆದರೆ (RB_ಎಡ(RB_ಪೋಷಕ(old, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) == old)\
				RB_ಎಡ(RB_ಪೋಷಕ(old, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = elm;\
			ಇಲ್ಲದಿದ್ದರೆ						\
				RB_ಬಲ(RB_ಪೋಷಕ(old, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = elm;\
			RB_AUGMENT(RB_ಪೋಷಕ(old, ಕ್ಷೇತ್ರ));		\
		} ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬೇರು(ತಲೆ) = elm;				\
		RB_ಪೋಷಕ(RB_ಎಡ(old, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = elm;		\
		ಆದರೆ (RB_ಬಲ(old, ಕ್ಷೇತ್ರ))				\
			RB_ಪೋಷಕ(RB_ಬಲ(old, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ) = elm;	\
		ಆದರೆ (ಪೋಷಕ) {						\
			ಎಡ = ಪೋಷಕ;					\
			ಮಾಡು {						\
				RB_AUGMENT(ಎಡ);			\
			} ಆಗ ((ಎಡ = RB_ಪೋಷಕ(ಎಡ, ಕ್ಷೇತ್ರ)));	\
		}							\
		ಹೋಗು color;						\
	}								\
	ಪೋಷಕ = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);					\
	color = RB_COLOR(elm, ಕ್ಷೇತ್ರ);					\
	ಆದರೆ (ಮಗು)							\
		RB_ಪೋಷಕ(ಮಗು, ಕ್ಷೇತ್ರ) = ಪೋಷಕ;			\
	ಆದರೆ (ಪೋಷಕ) {							\
		ಆದರೆ (RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) == elm)			\
			RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = ಮಗು;			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = ಮಗು;		\
		RB_AUGMENT(ಪೋಷಕ);					\
	} ಇಲ್ಲದಿದ್ದರೆ								\
		RB_ಬೇರು(ತಲೆ) = ಮಗು;					\
color:									\
	ಆದರೆ (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(ತಲೆ, ಪೋಷಕ, ಮಗು);		\
	ಹಿಂತಿರುಗಿ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ರಚನೆ type *							\
name##_RB_INSERT(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ರಚನೆ type *tmp;						\
	ರಚನೆ type *ಪೋಷಕ = ಖಾಲಿ;					\
	ಪೂರ್ಣಾಂಕ comp = 0;							\
	tmp = RB_ಬೇರು(ತಲೆ);						\
	ಆಗ (tmp) {							\
		ಪೋಷಕ = tmp;						\
		comp = (cmp)(elm, ಪೋಷಕ);				\
		ಆದರೆ (comp < 0)						\
			tmp = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			ಹಿಂತಿರುಗಿ (tmp);					\
	}								\
	RB_ಗಣ(elm, ಪೋಷಕ, ಕ್ಷೇತ್ರ);					\
	ಆದರೆ (ಪೋಷಕ != ಖಾಲಿ) {						\
		ಆದರೆ (comp < 0)						\
			RB_ಎಡ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = elm;			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			RB_ಬಲ(ಪೋಷಕ, ಕ್ಷೇತ್ರ) = elm;			\
		RB_AUGMENT(ಪೋಷಕ);					\
	} ಇಲ್ಲದಿದ್ದರೆ								\
		RB_ಬೇರು(ತಲೆ) = elm;					\
	name##_RB_INSERT_COLOR(ತಲೆ, elm);				\
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ರಚನೆ type *							\
name##_RB_FIND(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ರಚನೆ type *tmp = RB_ಬೇರು(ತಲೆ);				\
	ಪೂರ್ಣಾಂಕ comp;							\
	ಆಗ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ಆದರೆ (comp < 0)						\
			tmp = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			ಹಿಂತಿರುಗಿ (tmp);					\
	}								\
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ರಚನೆ type *							\
name##_RB_NFIND(ರಚನೆ name *ತಲೆ, ರಚನೆ type *elm)			\
{									\
	ರಚನೆ type *tmp = RB_ಬೇರು(ತಲೆ);				\
	ರಚನೆ type *res = ಖಾಲಿ;					\
	ಪೂರ್ಣಾಂಕ comp;							\
	ಆಗ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ಆದರೆ (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ);			\
		}							\
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			ಹಿಂತಿರುಗಿ (tmp);					\
	}								\
	ಹಿಂತಿರುಗಿ (res);							\
}									\
									\
/* ARGSUSED */								\
attr ರಚನೆ type *							\
name##_RB_NEXT(ರಚನೆ type *elm)					\
{									\
	ಆದರೆ (RB_ಬಲ(elm, ಕ್ಷೇತ್ರ)) {					\
		elm = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);				\
		ಆಗ (RB_ಎಡ(elm, ಕ್ಷೇತ್ರ))				\
			elm = RB_ಎಡ(elm, ಕ್ಷೇತ್ರ);			\
	} ಇಲ್ಲದಿದ್ದರೆ {							\
		ಆದರೆ (RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) &&				\
		    (elm == RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ)))	\
			elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ {							\
			ಆಗ (RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) &&			\
			    (elm == RB_ಬಲ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ)))\
				elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);		\
			elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);			\
		}							\
	}								\
	ಹಿಂತಿರುಗಿ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ರಚನೆ type *							\
name##_RB_PREV(ರಚನೆ type *elm)					\
{									\
	ಆದರೆ (RB_ಎಡ(elm, ಕ್ಷೇತ್ರ)) {					\
		elm = RB_ಎಡ(elm, ಕ್ಷೇತ್ರ);				\
		ಆಗ (RB_ಬಲ(elm, ಕ್ಷೇತ್ರ))				\
			elm = RB_ಬಲ(elm, ಕ್ಷೇತ್ರ);			\
	} ಇಲ್ಲದಿದ್ದರೆ {							\
		ಆದರೆ (RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) &&				\
		    (elm == RB_ಬಲ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ)))	\
			elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ {							\
			ಆಗ (RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ) &&			\
			    (elm == RB_ಎಡ(RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ), ಕ್ಷೇತ್ರ)))\
				elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);		\
			elm = RB_ಪೋಷಕ(elm, ಕ್ಷೇತ್ರ);			\
		}							\
	}								\
	ಹಿಂತಿರುಗಿ (elm);							\
}									\
									\
attr ರಚನೆ type *							\
name##_RB_MINMAX(ರಚನೆ name *ತಲೆ, ಪೂರ್ಣಾಂಕ val)				\
{									\
	ರಚನೆ type *tmp = RB_ಬೇರು(ತಲೆ);				\
	ರಚನೆ type *ಪೋಷಕ = ಖಾಲಿ;					\
	ಆಗ (tmp) {							\
		ಪೋಷಕ = tmp;						\
		ಆದರೆ (val < 0)						\
			tmp = RB_ಎಡ(tmp, ಕ್ಷೇತ್ರ);			\
		ಇಲ್ಲದಿದ್ದರೆ							\
			tmp = RB_ಬಲ(tmp, ಕ್ಷೇತ್ರ);			\
	}								\
	ಹಿಂತಿರುಗಿ (ಪೋಷಕ);						\
}

#ವ್ಯಾಖ್ಯಾನಿಸು RB_NEGINF	-1
#ವ್ಯಾಖ್ಯಾನಿಸು RB_INF	1

#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಸೇರಿಸು(name, x, y)	name##_RB_INSERT(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಕಂಡುಹಿಡಿ(name, x, y)	name##_RB_FIND(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_ಮುಂದಿನ(name, x, y)	name##_RB_NEXT(y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_PREV(name, x, y)	name##_RB_PREV(y)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#ವ್ಯಾಖ್ಯಾನಿಸು RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#ವ್ಯಾಖ್ಯಾನಿಸು RB_FOREACH(x, name, ತಲೆ)					\
	ಗಾಗಿ ((x) = RB_MIN(name, ತಲೆ);					\
	     (x) != ಖಾಲಿ;						\
	     (x) = name##_RB_NEXT(x))

#ವ್ಯಾಖ್ಯಾನಿಸು RB_FOREACH_ಸುರಕ್ಷಿತ(x, name, ತಲೆ, y)				\
	ಗಾಗಿ ((x) = RB_MIN(name, ತಲೆ);					\
	    ((x) != ಖಾಲಿ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#ವ್ಯಾಖ್ಯಾನಿಸು RB_FOREACH_ಹಿಮ್ಮುಖ(x, name, ತಲೆ)				\
	ಗಾಗಿ ((x) = RB_MAX(name, ತಲೆ);					\
	     (x) != ಖಾಲಿ;						\
	     (x) = name##_RB_PREV(x))

#ವ್ಯಾಖ್ಯಾನಿಸು RB_FOREACH_ಹಿಮ್ಮುಖ_ಸುರಕ್ಷಿತ(x, name, ತಲೆ, y)			\
	ಗಾಗಿ ((x) = RB_MAX(name, ತಲೆ);					\
	    ((x) != ಖಾಲಿ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#ಆದರೆ_ಅಂತ್ಯ	/* _SYS_TREE_H_ */
