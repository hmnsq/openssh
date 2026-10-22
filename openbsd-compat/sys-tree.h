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
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_ವೃಕ್ಷ_H
#define	SYS_ವೃಕ್ಷ_H

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

#define SPLAY_HEAD(name, type)						\
ಸಂರಚನಾ name {								\
	ಸಂರಚನಾ type *sph_ಬೇರು; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(ಬೇರು)						\
	{ ರಿಕ್ತ }

#define SPLAY_INIT(ಬೇರು) ಕುರು {						\
	(ಬೇರು)->sph_ಬೇರು = ರಿಕ್ತ;					\
} ಯಾವತ್ (0)

#define SPLAY_ENTRY(type)						\
ಸಂರಚನಾ {								\
	ಸಂರಚನಾ type *spe_ಎಡ; /* left element */			\
	ಸಂರಚನಾ type *spe_ಬಲ; /* right element */			\
}

#define SPLAY_ಎಡ(elm, field)		(elm)->field.spe_ಎಡ
#define SPLAY_ಬಲ(elm, field)		(elm)->field.spe_ಬಲ
#define SPLAY_ಬೇರು(head)		(head)->sph_ಬೇರು
#define SPLAY_EMPTY(head)		(SPLAY_ಬೇರು(head) == ರಿಕ್ತ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_ಬಲ(head, tmp, field) ಕುರು {			\
	SPLAY_ಎಡ((head)->sph_ಬೇರು, field) = SPLAY_ಬಲ(tmp, field);	\
	SPLAY_ಬಲ(tmp, field) = (head)->sph_ಬೇರು;			\
	(head)->sph_ಬೇರು = tmp;						\
} ಯಾವತ್ (0)
	
#define SPLAY_ROTATE_ಎಡ(head, tmp, field) ಕುರು {			\
	SPLAY_ಬಲ((head)->sph_ಬೇರು, field) = SPLAY_ಎಡ(tmp, field);	\
	SPLAY_ಎಡ(tmp, field) = (head)->sph_ಬೇರು;			\
	(head)->sph_ಬೇರು = tmp;						\
} ಯಾವತ್ (0)

#define SPLAY_LINKLEFT(head, tmp, field) ಕುರು {				\
	SPLAY_ಎಡ(tmp, field) = (head)->sph_ಬೇರು;			\
	tmp = (head)->sph_ಬೇರು;						\
	(head)->sph_ಬೇರು = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);		\
} ಯಾವತ್ (0)

#define SPLAY_LINKRIGHT(head, tmp, field) ಕುರು {				\
	SPLAY_ಬಲ(tmp, field) = (head)->sph_ಬೇರು;			\
	tmp = (head)->sph_ಬೇರು;						\
	(head)->sph_ಬೇರು = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);	\
} ಯಾವತ್ (0)

#define SPLAY_ASSEMBLE(head, ಗಂಟು, ಎಡ, ಬಲ, field) ಕುರು {		\
	SPLAY_ಬಲ(ಎಡ, field) = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);	\
	SPLAY_ಎಡ(ಬಲ, field) = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);\
	SPLAY_ಎಡ((head)->sph_ಬೇರು, field) = SPLAY_ಬಲ(ಗಂಟು, field);	\
	SPLAY_ಬಲ((head)->sph_ಬೇರು, field) = SPLAY_ಎಡ(ಗಂಟು, field);	\
} ಯಾವತ್ (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
ಶೂನ್ಯ name##_SPLAY(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);			\
ಶೂನ್ಯ name##_SPLAY_MINMAX(ಸಂರಚನಾ name *, ಪೂರ್ಣಾಙ್ಕ);				\
ಸಂರಚನಾ type *name##_SPLAY_INSERT(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);		\
ಸಂರಚನಾ type *name##_SPLAY_REMOVE(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);		\
									\
/* Finds the node with the same key as elm */				\
ಸ್ಥಿರ __inline ಸಂರಚನಾ type *						\
name##_SPLAY_FIND(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಯದಿ (SPLAY_EMPTY(head))						\
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);						\
	name##_SPLAY(head, elm);					\
	ಯದಿ ((cmp)(elm, (head)->sph_ಬೇರು) == 0)				\
		ಪ್ರತ್ಯಾಗಮ (head->sph_ಬೇರು);				\
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);							\
}									\
									\
ಸ್ಥಿರ __inline ಸಂರಚನಾ type *						\
name##_SPLAY_NEXT(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	ಯದಿ (SPLAY_ಬಲ(elm, field) != ರಿಕ್ತ) {				\
		elm = SPLAY_ಬಲ(elm, field);				\
		ಯಾವತ್ (SPLAY_ಎಡ(elm, field) != ರಿಕ್ತ) {		\
			elm = SPLAY_ಎಡ(elm, field);			\
		}							\
	} ಅನ್ಯಥಾ								\
		elm = ರಿಕ್ತ;						\
	ಪ್ರತ್ಯಾಗಮ (elm);							\
}									\
									\
ಸ್ಥಿರ __inline ಸಂರಚನಾ type *						\
name##_SPLAY_MIN_MAX(ಸಂರಚನಾ name *head, ಪೂರ್ಣಾಙ್ಕ val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        ಪ್ರತ್ಯಾಗಮ (SPLAY_ಬೇರು(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
ಸಂರಚನಾ type *								\
name##_SPLAY_INSERT(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)		\
{									\
    ಯದಿ (SPLAY_EMPTY(head)) {						\
	    SPLAY_ಎಡ(elm, field) = SPLAY_ಬಲ(elm, field) = ರಿಕ್ತ;	\
    } ಅನ್ಯಥಾ {								\
	    ಪೂರ್ಣಾಙ್ಕ __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_ಬೇರು);			\
	    ಯದಿ(__comp < 0) {						\
		    SPLAY_ಎಡ(elm, field) = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);\
		    SPLAY_ಬಲ(elm, field) = (head)->sph_ಬೇರು;		\
		    SPLAY_ಎಡ((head)->sph_ಬೇರು, field) = ರಿಕ್ತ;		\
	    } ಅನ್ಯಥಾ ಯದಿ (__comp > 0) {					\
		    SPLAY_ಬಲ(elm, field) = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);\
		    SPLAY_ಎಡ(elm, field) = (head)->sph_ಬೇರು;		\
		    SPLAY_ಬಲ((head)->sph_ಬೇರು, field) = ರಿಕ್ತ;	\
	    } ಅನ್ಯಥಾ							\
		    ಪ್ರತ್ಯಾಗಮ ((head)->sph_ಬೇರು);				\
    }									\
    (head)->sph_ಬೇರು = (elm);						\
    ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);							\
}									\
									\
ಸಂರಚನಾ type *								\
name##_SPLAY_REMOVE(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)		\
{									\
	ಸಂರಚನಾ type *__tmp;						\
	ಯದಿ (SPLAY_EMPTY(head))						\
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);						\
	name##_SPLAY(head, elm);					\
	ಯದಿ ((cmp)(elm, (head)->sph_ಬೇರು) == 0) {			\
		ಯದಿ (SPLAY_ಎಡ((head)->sph_ಬೇರು, field) == ರಿಕ್ತ) {	\
			(head)->sph_ಬೇರು = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);\
		} ಅನ್ಯಥಾ {						\
			__tmp = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);	\
			(head)->sph_ಬೇರು = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_ಬಲ((head)->sph_ಬೇರು, field) = __tmp;	\
		}							\
		ಪ್ರತ್ಯಾಗಮ (elm);						\
	}								\
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);							\
}									\
									\
ಶೂನ್ಯ									\
name##_SPLAY(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಸಂರಚನಾ type __node, *__left, *__right, *__tmp;			\
	ಪೂರ್ಣಾಙ್ಕ __comp;							\
\
	SPLAY_ಎಡ(&__node, field) = SPLAY_ಬಲ(&__node, field) = ರಿಕ್ತ;\
	__left = __right = &__node;					\
\
	ಯಾವತ್ ((__comp = (cmp)(elm, (head)->sph_ಬೇರು))) {		\
		ಯದಿ (__comp < 0) {					\
			__tmp = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);	\
			ಯದಿ (__tmp == ರಿಕ್ತ)				\
				ಭಙ್ಗ;					\
			ಯದಿ ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ಬಲ(head, __tmp, field);	\
				ಯದಿ (SPLAY_ಎಡ((head)->sph_ಬೇರು, field) == ರಿಕ್ತ)\
					ಭಙ್ಗ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} ಅನ್ಯಥಾ ಯದಿ (__comp > 0) {				\
			__tmp = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);	\
			ಯದಿ (__tmp == ರಿಕ್ತ)				\
				ಭಙ್ಗ;					\
			ಯದಿ ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ಎಡ(head, __tmp, field);	\
				ಯದಿ (SPLAY_ಬಲ((head)->sph_ಬೇರು, field) == ರಿಕ್ತ)\
					ಭಙ್ಗ;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
ಶೂನ್ಯ name##_SPLAY_MINMAX(ಸಂರಚನಾ name *head, ಪೂರ್ಣಾಙ್ಕ __comp) \
{									\
	ಸಂರಚನಾ type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ಎಡ(&__node, field) = SPLAY_ಬಲ(&__node, field) = ರಿಕ್ತ;\
	__left = __right = &__node;					\
\
	ಯಾವತ್ (1) {							\
		ಯದಿ (__comp < 0) {					\
			__tmp = SPLAY_ಎಡ((head)->sph_ಬೇರು, field);	\
			ಯದಿ (__tmp == ರಿಕ್ತ)				\
				ಭಙ್ಗ;					\
			ಯದಿ (__comp < 0){				\
				SPLAY_ROTATE_ಬಲ(head, __tmp, field);	\
				ಯದಿ (SPLAY_ಎಡ((head)->sph_ಬೇರು, field) == ರಿಕ್ತ)\
					ಭಙ್ಗ;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} ಅನ್ಯಥಾ ಯದಿ (__comp > 0) {				\
			__tmp = SPLAY_ಬಲ((head)->sph_ಬೇರು, field);	\
			ಯದಿ (__tmp == ರಿಕ್ತ)				\
				ಭಙ್ಗ;					\
			ಯದಿ (__comp > 0) {				\
				SPLAY_ROTATE_ಎಡ(head, __tmp, field);	\
				ಯದಿ (SPLAY_ಬಲ((head)->sph_ಬೇರು, field) == ರಿಕ್ತ)\
					ಭಙ್ಗ;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_ಸೇರಿಸು(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? ರಿಕ್ತ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? ರಿಕ್ತ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	ಪ್ರತಿ ((x) = SPLAY_MIN(name, head);				\
	     (x) != ರಿಕ್ತ;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
ಸಂರಚನಾ name {								\
	ಸಂರಚನಾ type *rbh_ಬೇರು; /* root of the tree */			\
}

#define RB_INITIALIZER(ಬೇರು)						\
	{ ರಿಕ್ತ }

#define RB_INIT(ಬೇರು) ಕುರು {						\
	(ಬೇರು)->rbh_ಬೇರು = ರಿಕ್ತ;					\
} ಯಾವತ್ (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
ಸಂರಚನಾ {								\
	ಸಂರಚನಾ type *rbe_ಎಡ;		/* left element */		\
	ಸಂರಚನಾ type *rbe_ಬಲ;		/* right element */		\
	ಸಂರಚನಾ type *rbe_parent;	/* parent element */		\
	ಪೂರ್ಣಾಙ್ಕ rbe_color;			/* node color */		\
}

#define RB_ಎಡ(elm, field)		(elm)->field.rbe_ಎಡ
#define RB_ಬಲ(elm, field)		(elm)->field.rbe_ಬಲ
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_ಬೇರು(head)			(head)->rbh_ಬೇರು
#define RB_EMPTY(head)			(RB_ಬೇರು(head) == ರಿಕ್ತ)

#define RB_SET(elm, parent, field) ಕುರು {					\
	RB_PARENT(elm, field) = parent;					\
	RB_ಎಡ(elm, field) = RB_ಬಲ(elm, field) = ರಿಕ್ತ;		\
	RB_COLOR(elm, field) = RB_RED;					\
} ಯಾವತ್ (0)

#define RB_SET_BLACKRED(black, red, field) ಕುರು {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} ಯಾವತ್ (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	ಕುರು {} ಯಾವತ್ (0)
#endif

#define RB_ROTATE_ಎಡ(head, elm, tmp, field) ಕುರು {			\
	(tmp) = RB_ಬಲ(elm, field);					\
	ಯದಿ ((RB_ಬಲ(elm, field) = RB_ಎಡ(tmp, field))) {		\
		RB_PARENT(RB_ಎಡ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ಯದಿ ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		ಯದಿ ((elm) == RB_ಎಡ(RB_PARENT(elm, field), field))	\
			RB_ಎಡ(RB_PARENT(elm, field), field) = (tmp);	\
		ಅನ್ಯಥಾ							\
			RB_ಬಲ(RB_PARENT(elm, field), field) = (tmp);	\
	} ಅನ್ಯಥಾ								\
		(head)->rbh_ಬೇರು = (tmp);				\
	RB_ಎಡ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ಯದಿ ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ಯಾವತ್ (0)

#define RB_ROTATE_ಬಲ(head, elm, tmp, field) ಕುರು {			\
	(tmp) = RB_ಎಡ(elm, field);					\
	ಯದಿ ((RB_ಎಡ(elm, field) = RB_ಬಲ(tmp, field))) {		\
		RB_PARENT(RB_ಬಲ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ಯದಿ ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		ಯದಿ ((elm) == RB_ಎಡ(RB_PARENT(elm, field), field))	\
			RB_ಎಡ(RB_PARENT(elm, field), field) = (tmp);	\
		ಅನ್ಯಥಾ							\
			RB_ಬಲ(RB_PARENT(elm, field), field) = (tmp);	\
	} ಅನ್ಯಥಾ								\
		(head)->rbh_ಬೇರು = (tmp);				\
	RB_ಬಲ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ಯದಿ ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ಯಾವತ್ (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ಸ್ಥಿರ)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr ಶೂನ್ಯ name##_RB_INSERT_COLOR(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);		\
attr ಶೂನ್ಯ name##_RB_REMOVE_COLOR(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *, ಸಂರಚನಾ type *);\
attr ಸಂರಚನಾ type *name##_RB_REMOVE(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);	\
attr ಸಂರಚನಾ type *name##_RB_INSERT(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);	\
attr ಸಂರಚನಾ type *name##_RB_FIND(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);		\
attr ಸಂರಚನಾ type *name##_RB_NFIND(ಸಂರಚನಾ name *, ಸಂರಚನಾ type *);	\
attr ಸಂರಚನಾ type *name##_RB_NEXT(ಸಂರಚನಾ type *);			\
attr ಸಂರಚನಾ type *name##_RB_PREV(ಸಂರಚನಾ type *);			\
attr ಸಂರಚನಾ type *name##_RB_MINMAX(ಸಂರಚನಾ name *, ಪೂರ್ಣಾಙ್ಕ);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) ಸ್ಥಿರ)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr ಶೂನ್ಯ								\
name##_RB_INSERT_COLOR(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)		\
{									\
	ಸಂರಚನಾ type *parent, *gparent, *tmp;				\
	ಯಾವತ್ ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		ಯದಿ (parent == RB_ಎಡ(gparent, field)) {		\
			tmp = RB_ಬಲ(gparent, field);			\
			ಯದಿ (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ಅನುವರ್ತ;				\
			}						\
			ಯದಿ (RB_ಬಲ(parent, field) == elm) {		\
				RB_ROTATE_ಎಡ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ಬಲ(head, gparent, tmp, field);	\
		} ಅನ್ಯಥಾ {						\
			tmp = RB_ಎಡ(gparent, field);			\
			ಯದಿ (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ಅನುವರ್ತ;				\
			}						\
			ಯದಿ (RB_ಎಡ(parent, field) == elm) {		\
				RB_ROTATE_ಬಲ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ಎಡ(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_ಬೇರು, field) = RB_BLACK;			\
}									\
									\
attr ಶೂನ್ಯ								\
name##_RB_REMOVE_COLOR(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *parent, ಸಂರಚನಾ type *elm) \
{									\
	ಸಂರಚನಾ type *tmp;						\
	ಯಾವತ್ ((elm == ರಿಕ್ತ || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_ಬೇರು(head)) {					\
		ಯದಿ (RB_ಎಡ(parent, field) == elm) {			\
			tmp = RB_ಬಲ(parent, field);			\
			ಯದಿ (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ಎಡ(head, parent, tmp, field);\
				tmp = RB_ಬಲ(parent, field);		\
			}						\
			ಯದಿ ((RB_ಎಡ(tmp, field) == ರಿಕ್ತ ||		\
			    RB_COLOR(RB_ಎಡ(tmp, field), field) == RB_BLACK) &&\
			    (RB_ಬಲ(tmp, field) == ರಿಕ್ತ ||		\
			    RB_COLOR(RB_ಬಲ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} ಅನ್ಯಥಾ {					\
				ಯದಿ (RB_ಬಲ(tmp, field) == ರಿಕ್ತ ||	\
				    RB_COLOR(RB_ಬಲ(tmp, field), field) == RB_BLACK) {\
					ಸಂರಚನಾ type *oleft;		\
					ಯದಿ ((oleft = RB_ಎಡ(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ಬಲ(head, tmp, oleft, field);\
					tmp = RB_ಬಲ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				ಯದಿ (RB_ಬಲ(tmp, field))		\
					RB_COLOR(RB_ಬಲ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ಎಡ(head, parent, tmp, field);\
				elm = RB_ಬೇರು(head);			\
				ಭಙ್ಗ;					\
			}						\
		} ಅನ್ಯಥಾ {						\
			tmp = RB_ಎಡ(parent, field);			\
			ಯದಿ (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ಬಲ(head, parent, tmp, field);\
				tmp = RB_ಎಡ(parent, field);		\
			}						\
			ಯದಿ ((RB_ಎಡ(tmp, field) == ರಿಕ್ತ ||		\
			    RB_COLOR(RB_ಎಡ(tmp, field), field) == RB_BLACK) &&\
			    (RB_ಬಲ(tmp, field) == ರಿಕ್ತ ||		\
			    RB_COLOR(RB_ಬಲ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} ಅನ್ಯಥಾ {					\
				ಯದಿ (RB_ಎಡ(tmp, field) == ರಿಕ್ತ ||	\
				    RB_COLOR(RB_ಎಡ(tmp, field), field) == RB_BLACK) {\
					ಸಂರಚನಾ type *oright;		\
					ಯದಿ ((oright = RB_ಬಲ(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ಎಡ(head, tmp, oright, field);\
					tmp = RB_ಎಡ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				ಯದಿ (RB_ಎಡ(tmp, field))		\
					RB_COLOR(RB_ಎಡ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ಬಲ(head, parent, tmp, field);\
				elm = RB_ಬೇರು(head);			\
				ಭಙ್ಗ;					\
			}						\
		}							\
	}								\
	ಯದಿ (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr ಸಂರಚನಾ type *							\
name##_RB_REMOVE(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಸಂರಚನಾ type *child, *parent, *old = elm;			\
	ಪೂರ್ಣಾಙ್ಕ color;							\
	ಯದಿ (RB_ಎಡ(elm, field) == ರಿಕ್ತ)				\
		child = RB_ಬಲ(elm, field);				\
	ಅನ್ಯಥಾ ಯದಿ (RB_ಬಲ(elm, field) == ರಿಕ್ತ)				\
		child = RB_ಎಡ(elm, field);				\
	ಅನ್ಯಥಾ {								\
		ಸಂರಚನಾ type *ಎಡ;					\
		elm = RB_ಬಲ(elm, field);				\
		ಯಾವತ್ ((ಎಡ = RB_ಎಡ(elm, field)))			\
			elm = ಎಡ;					\
		child = RB_ಬಲ(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		ಯದಿ (child)						\
			RB_PARENT(child, field) = parent;		\
		ಯದಿ (parent) {						\
			ಯದಿ (RB_ಎಡ(parent, field) == elm)		\
				RB_ಎಡ(parent, field) = child;		\
			ಅನ್ಯಥಾ						\
				RB_ಬಲ(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} ಅನ್ಯಥಾ							\
			RB_ಬೇರು(head) = child;				\
		ಯದಿ (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		ಯದಿ (RB_PARENT(old, field)) {				\
			ಯದಿ (RB_ಎಡ(RB_PARENT(old, field), field) == old)\
				RB_ಎಡ(RB_PARENT(old, field), field) = elm;\
			ಅನ್ಯಥಾ						\
				RB_ಬಲ(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} ಅನ್ಯಥಾ							\
			RB_ಬೇರು(head) = elm;				\
		RB_PARENT(RB_ಎಡ(old, field), field) = elm;		\
		ಯದಿ (RB_ಬಲ(old, field))				\
			RB_PARENT(RB_ಬಲ(old, field), field) = elm;	\
		ಯದಿ (parent) {						\
			ಎಡ = parent;					\
			ಕುರು {						\
				RB_AUGMENT(ಎಡ);			\
			} ಯಾವತ್ ((ಎಡ = RB_PARENT(ಎಡ, field)));	\
		}							\
		ಗಚ್ಛ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	ಯದಿ (child)							\
		RB_PARENT(child, field) = parent;			\
	ಯದಿ (parent) {							\
		ಯದಿ (RB_ಎಡ(parent, field) == elm)			\
			RB_ಎಡ(parent, field) = child;			\
		ಅನ್ಯಥಾ							\
			RB_ಬಲ(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} ಅನ್ಯಥಾ								\
		RB_ಬೇರು(head) = child;					\
color:									\
	ಯದಿ (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	ಪ್ರತ್ಯಾಗಮ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ಸಂರಚನಾ type *							\
name##_RB_INSERT(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಸಂರಚನಾ type *tmp;						\
	ಸಂರಚನಾ type *parent = ರಿಕ್ತ;					\
	ಪೂರ್ಣಾಙ್ಕ comp = 0;							\
	tmp = RB_ಬೇರು(head);						\
	ಯಾವತ್ (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		ಯದಿ (comp < 0)						\
			tmp = RB_ಎಡ(tmp, field);			\
		ಅನ್ಯಥಾ ಯದಿ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, field);			\
		ಅನ್ಯಥಾ							\
			ಪ್ರತ್ಯಾಗಮ (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	ಯದಿ (parent != ರಿಕ್ತ) {						\
		ಯದಿ (comp < 0)						\
			RB_ಎಡ(parent, field) = elm;			\
		ಅನ್ಯಥಾ							\
			RB_ಬಲ(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} ಅನ್ಯಥಾ								\
		RB_ಬೇರು(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ಸಂರಚನಾ type *							\
name##_RB_FIND(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಸಂರಚನಾ type *tmp = RB_ಬೇರು(head);				\
	ಪೂರ್ಣಾಙ್ಕ comp;							\
	ಯಾವತ್ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ಯದಿ (comp < 0)						\
			tmp = RB_ಎಡ(tmp, field);			\
		ಅನ್ಯಥಾ ಯದಿ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, field);			\
		ಅನ್ಯಥಾ							\
			ಪ್ರತ್ಯಾಗಮ (tmp);					\
	}								\
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ಸಂರಚನಾ type *							\
name##_RB_NFIND(ಸಂರಚನಾ name *head, ಸಂರಚನಾ type *elm)			\
{									\
	ಸಂರಚನಾ type *tmp = RB_ಬೇರು(head);				\
	ಸಂರಚನಾ type *res = ರಿಕ್ತ;					\
	ಪೂರ್ಣಾಙ್ಕ comp;							\
	ಯಾವತ್ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ಯದಿ (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ಎಡ(tmp, field);			\
		}							\
		ಅನ್ಯಥಾ ಯದಿ (comp > 0)					\
			tmp = RB_ಬಲ(tmp, field);			\
		ಅನ್ಯಥಾ							\
			ಪ್ರತ್ಯಾಗಮ (tmp);					\
	}								\
	ಪ್ರತ್ಯಾಗಮ (res);							\
}									\
									\
/* ARGSUSED */								\
attr ಸಂರಚನಾ type *							\
name##_RB_NEXT(ಸಂರಚನಾ type *elm)					\
{									\
	ಯದಿ (RB_ಬಲ(elm, field)) {					\
		elm = RB_ಬಲ(elm, field);				\
		ಯಾವತ್ (RB_ಎಡ(elm, field))				\
			elm = RB_ಎಡ(elm, field);			\
	} ಅನ್ಯಥಾ {							\
		ಯದಿ (RB_PARENT(elm, field) &&				\
		    (elm == RB_ಎಡ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		ಅನ್ಯಥಾ {							\
			ಯಾವತ್ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ಬಲ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ಪ್ರತ್ಯಾಗಮ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ಸಂರಚನಾ type *							\
name##_RB_PREV(ಸಂರಚನಾ type *elm)					\
{									\
	ಯದಿ (RB_ಎಡ(elm, field)) {					\
		elm = RB_ಎಡ(elm, field);				\
		ಯಾವತ್ (RB_ಬಲ(elm, field))				\
			elm = RB_ಬಲ(elm, field);			\
	} ಅನ್ಯಥಾ {							\
		ಯದಿ (RB_PARENT(elm, field) &&				\
		    (elm == RB_ಬಲ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		ಅನ್ಯಥಾ {							\
			ಯಾವತ್ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ಎಡ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	ಪ್ರತ್ಯಾಗಮ (elm);							\
}									\
									\
attr ಸಂರಚನಾ type *							\
name##_RB_MINMAX(ಸಂರಚನಾ name *head, ಪೂರ್ಣಾಙ್ಕ val)				\
{									\
	ಸಂರಚನಾ type *tmp = RB_ಬೇರು(head);				\
	ಸಂರಚನಾ type *parent = ರಿಕ್ತ;					\
	ಯಾವತ್ (tmp) {							\
		parent = tmp;						\
		ಯದಿ (val < 0)						\
			tmp = RB_ಎಡ(tmp, field);			\
		ಅನ್ಯಥಾ							\
			tmp = RB_ಬಲ(tmp, field);			\
	}								\
	ಪ್ರತ್ಯಾಗಮ (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_ಸೇರಿಸು(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	ಪ್ರತಿ ((x) = RB_MIN(name, head);					\
	     (x) != ರಿಕ್ತ;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	ಪ್ರತಿ ((x) = RB_MIN(name, head);					\
	    ((x) != ರಿಕ್ತ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	ಪ್ರತಿ ((x) = RB_MAX(name, head);					\
	     (x) != ರಿಕ್ತ;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	ಪ್ರತಿ ((x) = RB_MAX(name, head);					\
	    ((x) != ರಿಕ್ತ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
