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

#include "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_पुनो_H
#define	SYS_पुनो_H

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
struct name {								\
	struct type *sph_उगात; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(उगात)						\
	{ NULL }

#define SPLAY_INIT(उगात) do {						\
	(उगात)->sph_उगात = NULL;					\
} while (0)

#define SPLAY_ENTRY(type)						\
struct {								\
	struct type *spe_कालिवा; /* left element */			\
	struct type *spe_कानान; /* right element */			\
}

#define SPLAY_कालिवा(elm, field)		(elm)->field.spe_कालिवा
#define SPLAY_कानान(elm, field)		(elm)->field.spe_कानान
#define SPLAY_उगात(head)		(head)->sph_उगात
#define SPLAY_EMPTY(head)		(SPLAY_उगात(head) == NULL)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_कानान(head, tmp, field) do {			\
	SPLAY_कालिवा((head)->sph_उगात, field) = SPLAY_कानान(tmp, field);	\
	SPLAY_कानान(tmp, field) = (head)->sph_उगात;			\
	(head)->sph_उगात = tmp;						\
} while (0)
	
#define SPLAY_ROTATE_कालिवा(head, tmp, field) do {			\
	SPLAY_कानान((head)->sph_उगात, field) = SPLAY_कालिवा(tmp, field);	\
	SPLAY_कालिवा(tmp, field) = (head)->sph_उगात;			\
	(head)->sph_उगात = tmp;						\
} while (0)

#define SPLAY_LINKLEFT(head, tmp, field) do {				\
	SPLAY_कालिवा(tmp, field) = (head)->sph_उगात;			\
	tmp = (head)->sph_उगात;						\
	(head)->sph_उगात = SPLAY_कालिवा((head)->sph_उगात, field);		\
} while (0)

#define SPLAY_LINKRIGHT(head, tmp, field) do {				\
	SPLAY_कानान(tmp, field) = (head)->sph_उगात;			\
	tmp = (head)->sph_उगात;						\
	(head)->sph_उगात = SPLAY_कानान((head)->sph_उगात, field);	\
} while (0)

#define SPLAY_ASSEMBLE(head, बुहोल, कालिवा, कानान, field) do {		\
	SPLAY_कानान(कालिवा, field) = SPLAY_कालिवा((head)->sph_उगात, field);	\
	SPLAY_कालिवा(कानान, field) = SPLAY_कानान((head)->sph_उगात, field);\
	SPLAY_कालिवा((head)->sph_उगात, field) = SPLAY_कानान(बुहोल, field);	\
	SPLAY_कानान((head)->sph_उगात, field) = SPLAY_कालिवा(बुहोल, field);	\
} while (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
void name##_SPLAY(struct name *, struct type *);			\
void name##_SPLAY_MINMAX(struct name *, int);				\
struct type *name##_SPLAY_INSERT(struct name *, struct type *);		\
struct type *name##_SPLAY_REMOVE(struct name *, struct type *);		\
									\
/* Finds the node with the same key as elm */				\
static __inline struct type *						\
name##_SPLAY_FIND(struct name *head, struct type *elm)			\
{									\
	if (SPLAY_EMPTY(head))						\
		return(NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_उगात) == 0)				\
		return (head->sph_उगात);				\
	return (NULL);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_NEXT(struct name *head, struct type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	if (SPLAY_कानान(elm, field) != NULL) {				\
		elm = SPLAY_कानान(elm, field);				\
		while (SPLAY_कालिवा(elm, field) != NULL) {		\
			elm = SPLAY_कालिवा(elm, field);			\
		}							\
	} else								\
		elm = NULL;						\
	return (elm);							\
}									\
									\
static __inline struct type *						\
name##_SPLAY_MIN_MAX(struct name *head, int val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        return (SPLAY_उगात(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
struct type *								\
name##_SPLAY_INSERT(struct name *head, struct type *elm)		\
{									\
    if (SPLAY_EMPTY(head)) {						\
	    SPLAY_कालिवा(elm, field) = SPLAY_कानान(elm, field) = NULL;	\
    } else {								\
	    int __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_उगात);			\
	    if(__comp < 0) {						\
		    SPLAY_कालिवा(elm, field) = SPLAY_कालिवा((head)->sph_उगात, field);\
		    SPLAY_कानान(elm, field) = (head)->sph_उगात;		\
		    SPLAY_कालिवा((head)->sph_उगात, field) = NULL;		\
	    } else if (__comp > 0) {					\
		    SPLAY_कानान(elm, field) = SPLAY_कानान((head)->sph_उगात, field);\
		    SPLAY_कालिवा(elm, field) = (head)->sph_उगात;		\
		    SPLAY_कानान((head)->sph_उगात, field) = NULL;	\
	    } else							\
		    return ((head)->sph_उगात);				\
    }									\
    (head)->sph_उगात = (elm);						\
    return (NULL);							\
}									\
									\
struct type *								\
name##_SPLAY_REMOVE(struct name *head, struct type *elm)		\
{									\
	struct type *__tmp;						\
	if (SPLAY_EMPTY(head))						\
		return (NULL);						\
	name##_SPLAY(head, elm);					\
	if ((cmp)(elm, (head)->sph_उगात) == 0) {			\
		if (SPLAY_कालिवा((head)->sph_उगात, field) == NULL) {	\
			(head)->sph_उगात = SPLAY_कानान((head)->sph_उगात, field);\
		} else {						\
			__tmp = SPLAY_कानान((head)->sph_उगात, field);	\
			(head)->sph_उगात = SPLAY_कालिवा((head)->sph_उगात, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_कानान((head)->sph_उगात, field) = __tmp;	\
		}							\
		return (elm);						\
	}								\
	return (NULL);							\
}									\
									\
void									\
name##_SPLAY(struct name *head, struct type *elm)			\
{									\
	struct type __node, *__left, *__right, *__tmp;			\
	int __comp;							\
\
	SPLAY_कालिवा(&__node, field) = SPLAY_कानान(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while ((__comp = (cmp)(elm, (head)->sph_उगात))) {		\
		if (__comp < 0) {					\
			__tmp = SPLAY_कालिवा((head)->sph_उगात, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_कानान(head, __tmp, field);	\
				if (SPLAY_कालिवा((head)->sph_उगात, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_कानान((head)->sph_उगात, field);	\
			if (__tmp == NULL)				\
				break;					\
			if ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_कालिवा(head, __tmp, field);	\
				if (SPLAY_कानान((head)->sph_उगात, field) == NULL)\
					break;				\
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
void name##_SPLAY_MINMAX(struct name *head, int __comp) \
{									\
	struct type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_कालिवा(&__node, field) = SPLAY_कानान(&__node, field) = NULL;\
	__left = __right = &__node;					\
\
	while (1) {							\
		if (__comp < 0) {					\
			__tmp = SPLAY_कालिवा((head)->sph_उगात, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp < 0){				\
				SPLAY_ROTATE_कानान(head, __tmp, field);	\
				if (SPLAY_कालिवा((head)->sph_उगात, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} else if (__comp > 0) {				\
			__tmp = SPLAY_कानान((head)->sph_उगात, field);	\
			if (__tmp == NULL)				\
				break;					\
			if (__comp > 0) {				\
				SPLAY_ROTATE_कालिवा(head, __tmp, field);	\
				if (SPLAY_कानान((head)->sph_उगात, field) == NULL)\
					break;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_इसिंगित(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? NULL	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	for ((x) = SPLAY_MIN(name, head);				\
	     (x) != NULL;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
struct name {								\
	struct type *rbh_उगात; /* root of the tree */			\
}

#define RB_INITIALIZER(उगात)						\
	{ NULL }

#define RB_INIT(उगात) do {						\
	(उगात)->rbh_उगात = NULL;					\
} while (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
struct {								\
	struct type *rbe_कालिवा;		/* left element */		\
	struct type *rbe_कानान;		/* right element */		\
	struct type *rbe_parent;	/* parent element */		\
	int rbe_color;			/* node color */		\
}

#define RB_कालिवा(elm, field)		(elm)->field.rbe_कालिवा
#define RB_कानान(elm, field)		(elm)->field.rbe_कानान
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_उगात(head)			(head)->rbh_उगात
#define RB_EMPTY(head)			(RB_उगात(head) == NULL)

#define RB_SET(elm, parent, field) do {					\
	RB_PARENT(elm, field) = parent;					\
	RB_कालिवा(elm, field) = RB_कानान(elm, field) = NULL;		\
	RB_COLOR(elm, field) = RB_RED;					\
} while (0)

#define RB_SET_BLACKRED(black, red, field) do {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} while (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	do {} while (0)
#endif

#define RB_ROTATE_कालिवा(head, elm, tmp, field) do {			\
	(tmp) = RB_कानान(elm, field);					\
	if ((RB_कानान(elm, field) = RB_कालिवा(tmp, field))) {		\
		RB_PARENT(RB_कालिवा(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		if ((elm) == RB_कालिवा(RB_PARENT(elm, field), field))	\
			RB_कालिवा(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_कानान(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_उगात = (tmp);				\
	RB_कालिवा(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while (0)

#define RB_ROTATE_कानान(head, elm, tmp, field) do {			\
	(tmp) = RB_कालिवा(elm, field);					\
	if ((RB_कालिवा(elm, field) = RB_कानान(tmp, field))) {		\
		RB_PARENT(RB_कानान(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	if ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		if ((elm) == RB_कालिवा(RB_PARENT(elm, field), field))	\
			RB_कालिवा(RB_PARENT(elm, field), field) = (tmp);	\
		else							\
			RB_कानान(RB_PARENT(elm, field), field) = (tmp);	\
	} else								\
		(head)->rbh_उगात = (tmp);				\
	RB_कानान(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	if ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} while (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) static)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr void name##_RB_INSERT_COLOR(struct name *, struct type *);		\
attr void name##_RB_REMOVE_COLOR(struct name *, struct type *, struct type *);\
attr struct type *name##_RB_REMOVE(struct name *, struct type *);	\
attr struct type *name##_RB_INSERT(struct name *, struct type *);	\
attr struct type *name##_RB_FIND(struct name *, struct type *);		\
attr struct type *name##_RB_NFIND(struct name *, struct type *);	\
attr struct type *name##_RB_NEXT(struct type *);			\
attr struct type *name##_RB_PREV(struct type *);			\
attr struct type *name##_RB_MINMAX(struct name *, int);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) static)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr void								\
name##_RB_INSERT_COLOR(struct name *head, struct type *elm)		\
{									\
	struct type *parent, *gparent, *tmp;				\
	while ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		if (parent == RB_कालिवा(gparent, field)) {		\
			tmp = RB_कानान(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_कानान(parent, field) == elm) {		\
				RB_ROTATE_कालिवा(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_कानान(head, gparent, tmp, field);	\
		} else {						\
			tmp = RB_कालिवा(gparent, field);			\
			if (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				continue;				\
			}						\
			if (RB_कालिवा(parent, field) == elm) {		\
				RB_ROTATE_कानान(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_कालिवा(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_उगात, field) = RB_BLACK;			\
}									\
									\
attr void								\
name##_RB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm) \
{									\
	struct type *tmp;						\
	while ((elm == NULL || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_उगात(head)) {					\
		if (RB_कालिवा(parent, field) == elm) {			\
			tmp = RB_कानान(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_कालिवा(head, parent, tmp, field);\
				tmp = RB_कानान(parent, field);		\
			}						\
			if ((RB_कालिवा(tmp, field) == NULL ||		\
			    RB_COLOR(RB_कालिवा(tmp, field), field) == RB_BLACK) &&\
			    (RB_कानान(tmp, field) == NULL ||		\
			    RB_COLOR(RB_कानान(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_कानान(tmp, field) == NULL ||	\
				    RB_COLOR(RB_कानान(tmp, field), field) == RB_BLACK) {\
					struct type *oleft;		\
					if ((oleft = RB_कालिवा(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_कानान(head, tmp, oleft, field);\
					tmp = RB_कानान(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_कानान(tmp, field))		\
					RB_COLOR(RB_कानान(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_कालिवा(head, parent, tmp, field);\
				elm = RB_उगात(head);			\
				break;					\
			}						\
		} else {						\
			tmp = RB_कालिवा(parent, field);			\
			if (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_कानान(head, parent, tmp, field);\
				tmp = RB_कालिवा(parent, field);		\
			}						\
			if ((RB_कालिवा(tmp, field) == NULL ||		\
			    RB_COLOR(RB_कालिवा(tmp, field), field) == RB_BLACK) &&\
			    (RB_कानान(tmp, field) == NULL ||		\
			    RB_COLOR(RB_कानान(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} else {					\
				if (RB_कालिवा(tmp, field) == NULL ||	\
				    RB_COLOR(RB_कालिवा(tmp, field), field) == RB_BLACK) {\
					struct type *oright;		\
					if ((oright = RB_कानान(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_कालिवा(head, tmp, oright, field);\
					tmp = RB_कालिवा(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				if (RB_कालिवा(tmp, field))		\
					RB_COLOR(RB_कालिवा(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_कानान(head, parent, tmp, field);\
				elm = RB_उगात(head);			\
				break;					\
			}						\
		}							\
	}								\
	if (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr struct type *							\
name##_RB_REMOVE(struct name *head, struct type *elm)			\
{									\
	struct type *child, *parent, *old = elm;			\
	int color;							\
	if (RB_कालिवा(elm, field) == NULL)				\
		child = RB_कानान(elm, field);				\
	else if (RB_कानान(elm, field) == NULL)				\
		child = RB_कालिवा(elm, field);				\
	else {								\
		struct type *कालिवा;					\
		elm = RB_कानान(elm, field);				\
		while ((कालिवा = RB_कालिवा(elm, field)))			\
			elm = कालिवा;					\
		child = RB_कानान(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		if (child)						\
			RB_PARENT(child, field) = parent;		\
		if (parent) {						\
			if (RB_कालिवा(parent, field) == elm)		\
				RB_कालिवा(parent, field) = child;		\
			else						\
				RB_कानान(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} else							\
			RB_उगात(head) = child;				\
		if (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		if (RB_PARENT(old, field)) {				\
			if (RB_कालिवा(RB_PARENT(old, field), field) == old)\
				RB_कालिवा(RB_PARENT(old, field), field) = elm;\
			else						\
				RB_कानान(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} else							\
			RB_उगात(head) = elm;				\
		RB_PARENT(RB_कालिवा(old, field), field) = elm;		\
		if (RB_कानान(old, field))				\
			RB_PARENT(RB_कानान(old, field), field) = elm;	\
		if (parent) {						\
			कालिवा = parent;					\
			do {						\
				RB_AUGMENT(कालिवा);			\
			} while ((कालिवा = RB_PARENT(कालिवा, field)));	\
		}							\
		goto color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	if (child)							\
		RB_PARENT(child, field) = parent;			\
	if (parent) {							\
		if (RB_कालिवा(parent, field) == elm)			\
			RB_कालिवा(parent, field) = child;			\
		else							\
			RB_कानान(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} else								\
		RB_उगात(head) = child;					\
color:									\
	if (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	return (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr struct type *							\
name##_RB_INSERT(struct name *head, struct type *elm)			\
{									\
	struct type *tmp;						\
	struct type *parent = NULL;					\
	int comp = 0;							\
	tmp = RB_उगात(head);						\
	while (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		if (comp < 0)						\
			tmp = RB_कालिवा(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_कानान(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	if (parent != NULL) {						\
		if (comp < 0)						\
			RB_कालिवा(parent, field) = elm;			\
		else							\
			RB_कानान(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} else								\
		RB_उगात(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	return (NULL);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr struct type *							\
name##_RB_FIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_उगात(head);				\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0)						\
			tmp = RB_कालिवा(tmp, field);			\
		else if (comp > 0)					\
			tmp = RB_कानान(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (NULL);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr struct type *							\
name##_RB_NFIND(struct name *head, struct type *elm)			\
{									\
	struct type *tmp = RB_उगात(head);				\
	struct type *res = NULL;					\
	int comp;							\
	while (tmp) {							\
		comp = cmp(elm, tmp);					\
		if (comp < 0) {						\
			res = tmp;					\
			tmp = RB_कालिवा(tmp, field);			\
		}							\
		else if (comp > 0)					\
			tmp = RB_कानान(tmp, field);			\
		else							\
			return (tmp);					\
	}								\
	return (res);							\
}									\
									\
/* ARGSUSED */								\
attr struct type *							\
name##_RB_NEXT(struct type *elm)					\
{									\
	if (RB_कानान(elm, field)) {					\
		elm = RB_कानान(elm, field);				\
		while (RB_कालिवा(elm, field))				\
			elm = RB_कालिवा(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_कालिवा(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_कानान(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
/* ARGSUSED */								\
attr struct type *							\
name##_RB_PREV(struct type *elm)					\
{									\
	if (RB_कालिवा(elm, field)) {					\
		elm = RB_कालिवा(elm, field);				\
		while (RB_कानान(elm, field))				\
			elm = RB_कानान(elm, field);			\
	} else {							\
		if (RB_PARENT(elm, field) &&				\
		    (elm == RB_कानान(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		else {							\
			while (RB_PARENT(elm, field) &&			\
			    (elm == RB_कालिवा(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	return (elm);							\
}									\
									\
attr struct type *							\
name##_RB_MINMAX(struct name *head, int val)				\
{									\
	struct type *tmp = RB_उगात(head);				\
	struct type *parent = NULL;					\
	while (tmp) {							\
		parent = tmp;						\
		if (val < 0)						\
			tmp = RB_कालिवा(tmp, field);			\
		else							\
			tmp = RB_कानान(tmp, field);			\
	}								\
	return (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_इसिंगित(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	for ((x) = RB_MIN(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	for ((x) = RB_MAX(name, head);					\
	     (x) != NULL;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	for ((x) = RB_MAX(name, head);					\
	    ((x) != NULL) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
