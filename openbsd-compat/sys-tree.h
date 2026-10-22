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

#અન્તર્ભાવ "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_વૃક્ષ_H
#define	SYS_વૃક્ષ_H

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
સંરચના name {								\
	સંરચના type *sph_મૂળ; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(મૂળ)						\
	{ ખાલી }

#define SPLAY_INIT(મૂળ) કરો {						\
	(મૂળ)->sph_મૂળ = ખાલી;					\
} જ્યારે (0)

#define SPLAY_ENTRY(type)						\
સંરચના {								\
	સંરચના type *spe_ડાબું; /* left element */			\
	સંરચના type *spe_જમણું; /* right element */			\
}

#define SPLAY_ડાબું(elm, field)		(elm)->field.spe_ડાબું
#define SPLAY_જમણું(elm, field)		(elm)->field.spe_જમણું
#define SPLAY_મૂળ(head)		(head)->sph_મૂળ
#define SPLAY_EMPTY(head)		(SPLAY_મૂળ(head) == ખાલી)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_જમણું(head, tmp, field) કરો {			\
	SPLAY_ડાબું((head)->sph_મૂળ, field) = SPLAY_જમણું(tmp, field);	\
	SPLAY_જમણું(tmp, field) = (head)->sph_મૂળ;			\
	(head)->sph_મૂળ = tmp;						\
} જ્યારે (0)
	
#define SPLAY_ROTATE_ડાબું(head, tmp, field) કરો {			\
	SPLAY_જમણું((head)->sph_મૂળ, field) = SPLAY_ડાબું(tmp, field);	\
	SPLAY_ડાબું(tmp, field) = (head)->sph_મૂળ;			\
	(head)->sph_મૂળ = tmp;						\
} જ્યારે (0)

#define SPLAY_LINKLEFT(head, tmp, field) કરો {				\
	SPLAY_ડાબું(tmp, field) = (head)->sph_મૂળ;			\
	tmp = (head)->sph_મૂળ;						\
	(head)->sph_મૂળ = SPLAY_ડાબું((head)->sph_મૂળ, field);		\
} જ્યારે (0)

#define SPLAY_LINKRIGHT(head, tmp, field) કરો {				\
	SPLAY_જમણું(tmp, field) = (head)->sph_મૂળ;			\
	tmp = (head)->sph_મૂળ;						\
	(head)->sph_મૂળ = SPLAY_જમણું((head)->sph_મૂળ, field);	\
} જ્યારે (0)

#define SPLAY_ASSEMBLE(head, ગાંઠ, ડાબું, જમણું, field) કરો {		\
	SPLAY_જમણું(ડાબું, field) = SPLAY_ડાબું((head)->sph_મૂળ, field);	\
	SPLAY_ડાબું(જમણું, field) = SPLAY_જમણું((head)->sph_મૂળ, field);\
	SPLAY_ડાબું((head)->sph_મૂળ, field) = SPLAY_જમણું(ગાંઠ, field);	\
	SPLAY_જમણું((head)->sph_મૂળ, field) = SPLAY_ડાબું(ગાંઠ, field);	\
} જ્યારે (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
શૂન્ય name##_SPLAY(સંરચના name *, સંરચના type *);			\
શૂન્ય name##_SPLAY_MINMAX(સંરચના name *, પૂર્ણાંક);				\
સંરચના type *name##_SPLAY_INSERT(સંરચના name *, સંરચના type *);		\
સંરચના type *name##_SPLAY_REMOVE(સંરચના name *, સંરચના type *);		\
									\
/* Finds the node with the same key as elm */				\
સ્થિર __inline સંરચના type *						\
name##_SPLAY_FIND(સંરચના name *head, સંરચના type *elm)			\
{									\
	જો (SPLAY_EMPTY(head))						\
		પાછા(ખાલી);						\
	name##_SPLAY(head, elm);					\
	જો ((cmp)(elm, (head)->sph_મૂળ) == 0)				\
		પાછા (head->sph_મૂળ);				\
	પાછા (ખાલી);							\
}									\
									\
સ્થિર __inline સંરચના type *						\
name##_SPLAY_NEXT(સંરચના name *head, સંરચના type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	જો (SPLAY_જમણું(elm, field) != ખાલી) {				\
		elm = SPLAY_જમણું(elm, field);				\
		જ્યારે (SPLAY_ડાબું(elm, field) != ખાલી) {		\
			elm = SPLAY_ડાબું(elm, field);			\
		}							\
	} નહીંતર								\
		elm = ખાલી;						\
	પાછા (elm);							\
}									\
									\
સ્થિર __inline સંરચના type *						\
name##_SPLAY_MIN_MAX(સંરચના name *head, પૂર્ણાંક val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        પાછા (SPLAY_મૂળ(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
સંરચના type *								\
name##_SPLAY_INSERT(સંરચના name *head, સંરચના type *elm)		\
{									\
    જો (SPLAY_EMPTY(head)) {						\
	    SPLAY_ડાબું(elm, field) = SPLAY_જમણું(elm, field) = ખાલી;	\
    } નહીંતર {								\
	    પૂર્ણાંક __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_મૂળ);			\
	    જો(__comp < 0) {						\
		    SPLAY_ડાબું(elm, field) = SPLAY_ડાબું((head)->sph_મૂળ, field);\
		    SPLAY_જમણું(elm, field) = (head)->sph_મૂળ;		\
		    SPLAY_ડાબું((head)->sph_મૂળ, field) = ખાલી;		\
	    } નહીંતર જો (__comp > 0) {					\
		    SPLAY_જમણું(elm, field) = SPLAY_જમણું((head)->sph_મૂળ, field);\
		    SPLAY_ડાબું(elm, field) = (head)->sph_મૂળ;		\
		    SPLAY_જમણું((head)->sph_મૂળ, field) = ખાલી;	\
	    } નહીંતર							\
		    પાછા ((head)->sph_મૂળ);				\
    }									\
    (head)->sph_મૂળ = (elm);						\
    પાછા (ખાલી);							\
}									\
									\
સંરચના type *								\
name##_SPLAY_REMOVE(સંરચના name *head, સંરચના type *elm)		\
{									\
	સંરચના type *__tmp;						\
	જો (SPLAY_EMPTY(head))						\
		પાછા (ખાલી);						\
	name##_SPLAY(head, elm);					\
	જો ((cmp)(elm, (head)->sph_મૂળ) == 0) {			\
		જો (SPLAY_ડાબું((head)->sph_મૂળ, field) == ખાલી) {	\
			(head)->sph_મૂળ = SPLAY_જમણું((head)->sph_મૂળ, field);\
		} નહીંતર {						\
			__tmp = SPLAY_જમણું((head)->sph_મૂળ, field);	\
			(head)->sph_મૂળ = SPLAY_ડાબું((head)->sph_મૂળ, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_જમણું((head)->sph_મૂળ, field) = __tmp;	\
		}							\
		પાછા (elm);						\
	}								\
	પાછા (ખાલી);							\
}									\
									\
શૂન્ય									\
name##_SPLAY(સંરચના name *head, સંરચના type *elm)			\
{									\
	સંરચના type __node, *__left, *__right, *__tmp;			\
	પૂર્ણાંક __comp;							\
\
	SPLAY_ડાબું(&__node, field) = SPLAY_જમણું(&__node, field) = ખાલી;\
	__left = __right = &__node;					\
\
	જ્યારે ((__comp = (cmp)(elm, (head)->sph_મૂળ))) {		\
		જો (__comp < 0) {					\
			__tmp = SPLAY_ડાબું((head)->sph_મૂળ, field);	\
			જો (__tmp == ખાલી)				\
				તોડો;					\
			જો ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_જમણું(head, __tmp, field);	\
				જો (SPLAY_ડાબું((head)->sph_મૂળ, field) == ખાલી)\
					તોડો;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} નહીંતર જો (__comp > 0) {				\
			__tmp = SPLAY_જમણું((head)->sph_મૂળ, field);	\
			જો (__tmp == ખાલી)				\
				તોડો;					\
			જો ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ડાબું(head, __tmp, field);	\
				જો (SPLAY_જમણું((head)->sph_મૂળ, field) == ખાલી)\
					તોડો;				\
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
શૂન્ય name##_SPLAY_MINMAX(સંરચના name *head, પૂર્ણાંક __comp) \
{									\
	સંરચના type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ડાબું(&__node, field) = SPLAY_જમણું(&__node, field) = ખાલી;\
	__left = __right = &__node;					\
\
	જ્યારે (1) {							\
		જો (__comp < 0) {					\
			__tmp = SPLAY_ડાબું((head)->sph_મૂળ, field);	\
			જો (__tmp == ખાલી)				\
				તોડો;					\
			જો (__comp < 0){				\
				SPLAY_ROTATE_જમણું(head, __tmp, field);	\
				જો (SPLAY_ડાબું((head)->sph_મૂળ, field) == ખાલી)\
					તોડો;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} નહીંતર જો (__comp > 0) {				\
			__tmp = SPLAY_જમણું((head)->sph_મૂળ, field);	\
			જો (__tmp == ખાલી)				\
				તોડો;					\
			જો (__comp > 0) {				\
				SPLAY_ROTATE_ડાબું(head, __tmp, field);	\
				જો (SPLAY_જમણું((head)->sph_મૂળ, field) == ખાલી)\
					તોડો;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_ઉમેરો(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? ખાલી	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? ખાલી	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	માટે ((x) = SPLAY_MIN(name, head);				\
	     (x) != ખાલી;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
સંરચના name {								\
	સંરચના type *rbh_મૂળ; /* root of the tree */			\
}

#define RB_INITIALIZER(મૂળ)						\
	{ ખાલી }

#define RB_INIT(મૂળ) કરો {						\
	(મૂળ)->rbh_મૂળ = ખાલી;					\
} જ્યારે (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
સંરચના {								\
	સંરચના type *rbe_ડાબું;		/* left element */		\
	સંરચના type *rbe_જમણું;		/* right element */		\
	સંરચના type *rbe_parent;	/* parent element */		\
	પૂર્ણાંક rbe_color;			/* node color */		\
}

#define RB_ડાબું(elm, field)		(elm)->field.rbe_ડાબું
#define RB_જમણું(elm, field)		(elm)->field.rbe_જમણું
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_મૂળ(head)			(head)->rbh_મૂળ
#define RB_EMPTY(head)			(RB_મૂળ(head) == ખાલી)

#define RB_SET(elm, parent, field) કરો {					\
	RB_PARENT(elm, field) = parent;					\
	RB_ડાબું(elm, field) = RB_જમણું(elm, field) = ખાલી;		\
	RB_COLOR(elm, field) = RB_RED;					\
} જ્યારે (0)

#define RB_SET_BLACKRED(black, red, field) કરો {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} જ્યારે (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	કરો {} જ્યારે (0)
#endif

#define RB_ROTATE_ડાબું(head, elm, tmp, field) કરો {			\
	(tmp) = RB_જમણું(elm, field);					\
	જો ((RB_જમણું(elm, field) = RB_ડાબું(tmp, field))) {		\
		RB_PARENT(RB_ડાબું(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	જો ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		જો ((elm) == RB_ડાબું(RB_PARENT(elm, field), field))	\
			RB_ડાબું(RB_PARENT(elm, field), field) = (tmp);	\
		નહીંતર							\
			RB_જમણું(RB_PARENT(elm, field), field) = (tmp);	\
	} નહીંતર								\
		(head)->rbh_મૂળ = (tmp);				\
	RB_ડાબું(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	જો ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} જ્યારે (0)

#define RB_ROTATE_જમણું(head, elm, tmp, field) કરો {			\
	(tmp) = RB_ડાબું(elm, field);					\
	જો ((RB_ડાબું(elm, field) = RB_જમણું(tmp, field))) {		\
		RB_PARENT(RB_જમણું(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	જો ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		જો ((elm) == RB_ડાબું(RB_PARENT(elm, field), field))	\
			RB_ડાબું(RB_PARENT(elm, field), field) = (tmp);	\
		નહીંતર							\
			RB_જમણું(RB_PARENT(elm, field), field) = (tmp);	\
	} નહીંતર								\
		(head)->rbh_મૂળ = (tmp);				\
	RB_જમણું(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	જો ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} જ્યારે (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) સ્થિર)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr શૂન્ય name##_RB_INSERT_COLOR(સંરચના name *, સંરચના type *);		\
attr શૂન્ય name##_RB_REMOVE_COLOR(સંરચના name *, સંરચના type *, સંરચના type *);\
attr સંરચના type *name##_RB_REMOVE(સંરચના name *, સંરચના type *);	\
attr સંરચના type *name##_RB_INSERT(સંરચના name *, સંરચના type *);	\
attr સંરચના type *name##_RB_FIND(સંરચના name *, સંરચના type *);		\
attr સંરચના type *name##_RB_NFIND(સંરચના name *, સંરચના type *);	\
attr સંરચના type *name##_RB_NEXT(સંરચના type *);			\
attr સંરચના type *name##_RB_PREV(સંરચના type *);			\
attr સંરચના type *name##_RB_MINMAX(સંરચના name *, પૂર્ણાંક);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) સ્થિર)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr શૂન્ય								\
name##_RB_INSERT_COLOR(સંરચના name *head, સંરચના type *elm)		\
{									\
	સંરચના type *parent, *gparent, *tmp;				\
	જ્યારે ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		જો (parent == RB_ડાબું(gparent, field)) {		\
			tmp = RB_જમણું(gparent, field);			\
			જો (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ચાલુ;				\
			}						\
			જો (RB_જમણું(parent, field) == elm) {		\
				RB_ROTATE_ડાબું(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_જમણું(head, gparent, tmp, field);	\
		} નહીંતર {						\
			tmp = RB_ડાબું(gparent, field);			\
			જો (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				ચાલુ;				\
			}						\
			જો (RB_ડાબું(parent, field) == elm) {		\
				RB_ROTATE_જમણું(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ડાબું(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_મૂળ, field) = RB_BLACK;			\
}									\
									\
attr શૂન્ય								\
name##_RB_REMOVE_COLOR(સંરચના name *head, સંરચના type *parent, સંરચના type *elm) \
{									\
	સંરચના type *tmp;						\
	જ્યારે ((elm == ખાલી || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_મૂળ(head)) {					\
		જો (RB_ડાબું(parent, field) == elm) {			\
			tmp = RB_જમણું(parent, field);			\
			જો (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ડાબું(head, parent, tmp, field);\
				tmp = RB_જમણું(parent, field);		\
			}						\
			જો ((RB_ડાબું(tmp, field) == ખાલી ||		\
			    RB_COLOR(RB_ડાબું(tmp, field), field) == RB_BLACK) &&\
			    (RB_જમણું(tmp, field) == ખાલી ||		\
			    RB_COLOR(RB_જમણું(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} નહીંતર {					\
				જો (RB_જમણું(tmp, field) == ખાલી ||	\
				    RB_COLOR(RB_જમણું(tmp, field), field) == RB_BLACK) {\
					સંરચના type *oleft;		\
					જો ((oleft = RB_ડાબું(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_જમણું(head, tmp, oleft, field);\
					tmp = RB_જમણું(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				જો (RB_જમણું(tmp, field))		\
					RB_COLOR(RB_જમણું(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ડાબું(head, parent, tmp, field);\
				elm = RB_મૂળ(head);			\
				તોડો;					\
			}						\
		} નહીંતર {						\
			tmp = RB_ડાબું(parent, field);			\
			જો (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_જમણું(head, parent, tmp, field);\
				tmp = RB_ડાબું(parent, field);		\
			}						\
			જો ((RB_ડાબું(tmp, field) == ખાલી ||		\
			    RB_COLOR(RB_ડાબું(tmp, field), field) == RB_BLACK) &&\
			    (RB_જમણું(tmp, field) == ખાલી ||		\
			    RB_COLOR(RB_જમણું(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} નહીંતર {					\
				જો (RB_ડાબું(tmp, field) == ખાલી ||	\
				    RB_COLOR(RB_ડાબું(tmp, field), field) == RB_BLACK) {\
					સંરચના type *oright;		\
					જો ((oright = RB_જમણું(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ડાબું(head, tmp, oright, field);\
					tmp = RB_ડાબું(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				જો (RB_ડાબું(tmp, field))		\
					RB_COLOR(RB_ડાબું(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_જમણું(head, parent, tmp, field);\
				elm = RB_મૂળ(head);			\
				તોડો;					\
			}						\
		}							\
	}								\
	જો (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr સંરચના type *							\
name##_RB_REMOVE(સંરચના name *head, સંરચના type *elm)			\
{									\
	સંરચના type *child, *parent, *old = elm;			\
	પૂર્ણાંક color;							\
	જો (RB_ડાબું(elm, field) == ખાલી)				\
		child = RB_જમણું(elm, field);				\
	નહીંતર જો (RB_જમણું(elm, field) == ખાલી)				\
		child = RB_ડાબું(elm, field);				\
	નહીંતર {								\
		સંરચના type *ડાબું;					\
		elm = RB_જમણું(elm, field);				\
		જ્યારે ((ડાબું = RB_ડાબું(elm, field)))			\
			elm = ડાબું;					\
		child = RB_જમણું(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		જો (child)						\
			RB_PARENT(child, field) = parent;		\
		જો (parent) {						\
			જો (RB_ડાબું(parent, field) == elm)		\
				RB_ડાબું(parent, field) = child;		\
			નહીંતર						\
				RB_જમણું(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} નહીંતર							\
			RB_મૂળ(head) = child;				\
		જો (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		જો (RB_PARENT(old, field)) {				\
			જો (RB_ડાબું(RB_PARENT(old, field), field) == old)\
				RB_ડાબું(RB_PARENT(old, field), field) = elm;\
			નહીંતર						\
				RB_જમણું(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} નહીંતર							\
			RB_મૂળ(head) = elm;				\
		RB_PARENT(RB_ડાબું(old, field), field) = elm;		\
		જો (RB_જમણું(old, field))				\
			RB_PARENT(RB_જમણું(old, field), field) = elm;	\
		જો (parent) {						\
			ડાબું = parent;					\
			કરો {						\
				RB_AUGMENT(ડાબું);			\
			} જ્યારે ((ડાબું = RB_PARENT(ડાબું, field)));	\
		}							\
		જાઓ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	જો (child)							\
		RB_PARENT(child, field) = parent;			\
	જો (parent) {							\
		જો (RB_ડાબું(parent, field) == elm)			\
			RB_ડાબું(parent, field) = child;			\
		નહીંતર							\
			RB_જમણું(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} નહીંતર								\
		RB_મૂળ(head) = child;					\
color:									\
	જો (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	પાછા (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr સંરચના type *							\
name##_RB_INSERT(સંરચના name *head, સંરચના type *elm)			\
{									\
	સંરચના type *tmp;						\
	સંરચના type *parent = ખાલી;					\
	પૂર્ણાંક comp = 0;							\
	tmp = RB_મૂળ(head);						\
	જ્યારે (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		જો (comp < 0)						\
			tmp = RB_ડાબું(tmp, field);			\
		નહીંતર જો (comp > 0)					\
			tmp = RB_જમણું(tmp, field);			\
		નહીંતર							\
			પાછા (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	જો (parent != ખાલી) {						\
		જો (comp < 0)						\
			RB_ડાબું(parent, field) = elm;			\
		નહીંતર							\
			RB_જમણું(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} નહીંતર								\
		RB_મૂળ(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	પાછા (ખાલી);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr સંરચના type *							\
name##_RB_FIND(સંરચના name *head, સંરચના type *elm)			\
{									\
	સંરચના type *tmp = RB_મૂળ(head);				\
	પૂર્ણાંક comp;							\
	જ્યારે (tmp) {							\
		comp = cmp(elm, tmp);					\
		જો (comp < 0)						\
			tmp = RB_ડાબું(tmp, field);			\
		નહીંતર જો (comp > 0)					\
			tmp = RB_જમણું(tmp, field);			\
		નહીંતર							\
			પાછા (tmp);					\
	}								\
	પાછા (ખાલી);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr સંરચના type *							\
name##_RB_NFIND(સંરચના name *head, સંરચના type *elm)			\
{									\
	સંરચના type *tmp = RB_મૂળ(head);				\
	સંરચના type *res = ખાલી;					\
	પૂર્ણાંક comp;							\
	જ્યારે (tmp) {							\
		comp = cmp(elm, tmp);					\
		જો (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ડાબું(tmp, field);			\
		}							\
		નહીંતર જો (comp > 0)					\
			tmp = RB_જમણું(tmp, field);			\
		નહીંતર							\
			પાછા (tmp);					\
	}								\
	પાછા (res);							\
}									\
									\
/* ARGSUSED */								\
attr સંરચના type *							\
name##_RB_NEXT(સંરચના type *elm)					\
{									\
	જો (RB_જમણું(elm, field)) {					\
		elm = RB_જમણું(elm, field);				\
		જ્યારે (RB_ડાબું(elm, field))				\
			elm = RB_ડાબું(elm, field);			\
	} નહીંતર {							\
		જો (RB_PARENT(elm, field) &&				\
		    (elm == RB_ડાબું(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		નહીંતર {							\
			જ્યારે (RB_PARENT(elm, field) &&			\
			    (elm == RB_જમણું(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	પાછા (elm);							\
}									\
									\
/* ARGSUSED */								\
attr સંરચના type *							\
name##_RB_PREV(સંરચના type *elm)					\
{									\
	જો (RB_ડાબું(elm, field)) {					\
		elm = RB_ડાબું(elm, field);				\
		જ્યારે (RB_જમણું(elm, field))				\
			elm = RB_જમણું(elm, field);			\
	} નહીંતર {							\
		જો (RB_PARENT(elm, field) &&				\
		    (elm == RB_જમણું(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		નહીંતર {							\
			જ્યારે (RB_PARENT(elm, field) &&			\
			    (elm == RB_ડાબું(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	પાછા (elm);							\
}									\
									\
attr સંરચના type *							\
name##_RB_MINMAX(સંરચના name *head, પૂર્ણાંક val)				\
{									\
	સંરચના type *tmp = RB_મૂળ(head);				\
	સંરચના type *parent = ખાલી;					\
	જ્યારે (tmp) {							\
		parent = tmp;						\
		જો (val < 0)						\
			tmp = RB_ડાબું(tmp, field);			\
		નહીંતર							\
			tmp = RB_જમણું(tmp, field);			\
	}								\
	પાછા (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_ઉમેરો(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	માટે ((x) = RB_MIN(name, head);					\
	     (x) != ખાલી;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	માટે ((x) = RB_MIN(name, head);					\
	    ((x) != ખાલી) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	માટે ((x) = RB_MAX(name, head);					\
	     (x) != ખાલી;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	માટે ((x) = RB_MAX(name, head);					\
	    ((x) != ખાલી) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
