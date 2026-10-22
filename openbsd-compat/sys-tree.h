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

#अन्तर्भाव "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_वृक्ष_H
#define	SYS_वृक्ष_H

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
संरचना name {								\
	संरचना type *sph_मूळ; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(मूळ)						\
	{ रिक्त }

#define SPLAY_INIT(मूळ) करा {						\
	(मूळ)->sph_मूळ = रिक्त;					\
} पर्यंत (0)

#define SPLAY_ENTRY(type)						\
संरचना {								\
	संरचना type *spe_डावा; /* left element */			\
	संरचना type *spe_उजवा; /* right element */			\
}

#define SPLAY_डावा(elm, field)		(elm)->field.spe_डावा
#define SPLAY_उजवा(elm, field)		(elm)->field.spe_उजवा
#define SPLAY_मूळ(head)		(head)->sph_मूळ
#define SPLAY_EMPTY(head)		(SPLAY_मूळ(head) == रिक्त)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_उजवा(head, tmp, field) करा {			\
	SPLAY_डावा((head)->sph_मूळ, field) = SPLAY_उजवा(tmp, field);	\
	SPLAY_उजवा(tmp, field) = (head)->sph_मूळ;			\
	(head)->sph_मूळ = tmp;						\
} पर्यंत (0)
	
#define SPLAY_ROTATE_डावा(head, tmp, field) करा {			\
	SPLAY_उजवा((head)->sph_मूळ, field) = SPLAY_डावा(tmp, field);	\
	SPLAY_डावा(tmp, field) = (head)->sph_मूळ;			\
	(head)->sph_मूळ = tmp;						\
} पर्यंत (0)

#define SPLAY_LINKLEFT(head, tmp, field) करा {				\
	SPLAY_डावा(tmp, field) = (head)->sph_मूळ;			\
	tmp = (head)->sph_मूळ;						\
	(head)->sph_मूळ = SPLAY_डावा((head)->sph_मूळ, field);		\
} पर्यंत (0)

#define SPLAY_LINKRIGHT(head, tmp, field) करा {				\
	SPLAY_उजवा(tmp, field) = (head)->sph_मूळ;			\
	tmp = (head)->sph_मूळ;						\
	(head)->sph_मूळ = SPLAY_उजवा((head)->sph_मूळ, field);	\
} पर्यंत (0)

#define SPLAY_ASSEMBLE(head, गाठ, डावा, उजवा, field) करा {		\
	SPLAY_उजवा(डावा, field) = SPLAY_डावा((head)->sph_मूळ, field);	\
	SPLAY_डावा(उजवा, field) = SPLAY_उजवा((head)->sph_मूळ, field);\
	SPLAY_डावा((head)->sph_मूळ, field) = SPLAY_उजवा(गाठ, field);	\
	SPLAY_उजवा((head)->sph_मूळ, field) = SPLAY_डावा(गाठ, field);	\
} पर्यंत (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
शून्य name##_SPLAY(संरचना name *, संरचना type *);			\
शून्य name##_SPLAY_MINMAX(संरचना name *, पूर्णांक);				\
संरचना type *name##_SPLAY_INSERT(संरचना name *, संरचना type *);		\
संरचना type *name##_SPLAY_REMOVE(संरचना name *, संरचना type *);		\
									\
/* Finds the node with the same key as elm */				\
स्थिर __inline संरचना type *						\
name##_SPLAY_FIND(संरचना name *head, संरचना type *elm)			\
{									\
	जर (SPLAY_EMPTY(head))						\
		परत(रिक्त);						\
	name##_SPLAY(head, elm);					\
	जर ((cmp)(elm, (head)->sph_मूळ) == 0)				\
		परत (head->sph_मूळ);				\
	परत (रिक्त);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_NEXT(संरचना name *head, संरचना type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	जर (SPLAY_उजवा(elm, field) != रिक्त) {				\
		elm = SPLAY_उजवा(elm, field);				\
		पर्यंत (SPLAY_डावा(elm, field) != रिक्त) {		\
			elm = SPLAY_डावा(elm, field);			\
		}							\
	} अन्यथा								\
		elm = रिक्त;						\
	परत (elm);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_MIN_MAX(संरचना name *head, पूर्णांक val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        परत (SPLAY_मूळ(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
संरचना type *								\
name##_SPLAY_INSERT(संरचना name *head, संरचना type *elm)		\
{									\
    जर (SPLAY_EMPTY(head)) {						\
	    SPLAY_डावा(elm, field) = SPLAY_उजवा(elm, field) = रिक्त;	\
    } अन्यथा {								\
	    पूर्णांक __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_मूळ);			\
	    जर(__comp < 0) {						\
		    SPLAY_डावा(elm, field) = SPLAY_डावा((head)->sph_मूळ, field);\
		    SPLAY_उजवा(elm, field) = (head)->sph_मूळ;		\
		    SPLAY_डावा((head)->sph_मूळ, field) = रिक्त;		\
	    } अन्यथा जर (__comp > 0) {					\
		    SPLAY_उजवा(elm, field) = SPLAY_उजवा((head)->sph_मूळ, field);\
		    SPLAY_डावा(elm, field) = (head)->sph_मूळ;		\
		    SPLAY_उजवा((head)->sph_मूळ, field) = रिक्त;	\
	    } अन्यथा							\
		    परत ((head)->sph_मूळ);				\
    }									\
    (head)->sph_मूळ = (elm);						\
    परत (रिक्त);							\
}									\
									\
संरचना type *								\
name##_SPLAY_REMOVE(संरचना name *head, संरचना type *elm)		\
{									\
	संरचना type *__tmp;						\
	जर (SPLAY_EMPTY(head))						\
		परत (रिक्त);						\
	name##_SPLAY(head, elm);					\
	जर ((cmp)(elm, (head)->sph_मूळ) == 0) {			\
		जर (SPLAY_डावा((head)->sph_मूळ, field) == रिक्त) {	\
			(head)->sph_मूळ = SPLAY_उजवा((head)->sph_मूळ, field);\
		} अन्यथा {						\
			__tmp = SPLAY_उजवा((head)->sph_मूळ, field);	\
			(head)->sph_मूळ = SPLAY_डावा((head)->sph_मूळ, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_उजवा((head)->sph_मूळ, field) = __tmp;	\
		}							\
		परत (elm);						\
	}								\
	परत (रिक्त);							\
}									\
									\
शून्य									\
name##_SPLAY(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
	पूर्णांक __comp;							\
\
	SPLAY_डावा(&__node, field) = SPLAY_उजवा(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	पर्यंत ((__comp = (cmp)(elm, (head)->sph_मूळ))) {		\
		जर (__comp < 0) {					\
			__tmp = SPLAY_डावा((head)->sph_मूळ, field);	\
			जर (__tmp == रिक्त)				\
				थांबा;					\
			जर ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_उजवा(head, __tmp, field);	\
				जर (SPLAY_डावा((head)->sph_मूळ, field) == रिक्त)\
					थांबा;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अन्यथा जर (__comp > 0) {				\
			__tmp = SPLAY_उजवा((head)->sph_मूळ, field);	\
			जर (__tmp == रिक्त)				\
				थांबा;					\
			जर ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_डावा(head, __tmp, field);	\
				जर (SPLAY_उजवा((head)->sph_मूळ, field) == रिक्त)\
					थांबा;				\
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
शून्य name##_SPLAY_MINMAX(संरचना name *head, पूर्णांक __comp) \
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_डावा(&__node, field) = SPLAY_उजवा(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	पर्यंत (1) {							\
		जर (__comp < 0) {					\
			__tmp = SPLAY_डावा((head)->sph_मूळ, field);	\
			जर (__tmp == रिक्त)				\
				थांबा;					\
			जर (__comp < 0){				\
				SPLAY_ROTATE_उजवा(head, __tmp, field);	\
				जर (SPLAY_डावा((head)->sph_मूळ, field) == रिक्त)\
					थांबा;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अन्यथा जर (__comp > 0) {				\
			__tmp = SPLAY_उजवा((head)->sph_मूळ, field);	\
			जर (__tmp == रिक्त)				\
				थांबा;					\
			जर (__comp > 0) {				\
				SPLAY_ROTATE_डावा(head, __tmp, field);	\
				जर (SPLAY_उजवा((head)->sph_मूळ, field) == रिक्त)\
					थांबा;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_घाला(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	साठी ((x) = SPLAY_MIN(name, head);				\
	     (x) != रिक्त;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
संरचना name {								\
	संरचना type *rbh_मूळ; /* root of the tree */			\
}

#define RB_INITIALIZER(मूळ)						\
	{ रिक्त }

#define RB_INIT(मूळ) करा {						\
	(मूळ)->rbh_मूळ = रिक्त;					\
} पर्यंत (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
संरचना {								\
	संरचना type *rbe_डावा;		/* left element */		\
	संरचना type *rbe_उजवा;		/* right element */		\
	संरचना type *rbe_parent;	/* parent element */		\
	पूर्णांक rbe_color;			/* node color */		\
}

#define RB_डावा(elm, field)		(elm)->field.rbe_डावा
#define RB_उजवा(elm, field)		(elm)->field.rbe_उजवा
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_मूळ(head)			(head)->rbh_मूळ
#define RB_EMPTY(head)			(RB_मूळ(head) == रिक्त)

#define RB_SET(elm, parent, field) करा {					\
	RB_PARENT(elm, field) = parent;					\
	RB_डावा(elm, field) = RB_उजवा(elm, field) = रिक्त;		\
	RB_COLOR(elm, field) = RB_RED;					\
} पर्यंत (0)

#define RB_SET_BLACKRED(black, red, field) करा {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} पर्यंत (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	करा {} पर्यंत (0)
#endif

#define RB_ROTATE_डावा(head, elm, tmp, field) करा {			\
	(tmp) = RB_उजवा(elm, field);					\
	जर ((RB_उजवा(elm, field) = RB_डावा(tmp, field))) {		\
		RB_PARENT(RB_डावा(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	जर ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		जर ((elm) == RB_डावा(RB_PARENT(elm, field), field))	\
			RB_डावा(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_उजवा(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(head)->rbh_मूळ = (tmp);				\
	RB_डावा(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	जर ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} पर्यंत (0)

#define RB_ROTATE_उजवा(head, elm, tmp, field) करा {			\
	(tmp) = RB_डावा(elm, field);					\
	जर ((RB_डावा(elm, field) = RB_उजवा(tmp, field))) {		\
		RB_PARENT(RB_उजवा(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	जर ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		जर ((elm) == RB_डावा(RB_PARENT(elm, field), field))	\
			RB_डावा(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_उजवा(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(head)->rbh_मूळ = (tmp);				\
	RB_उजवा(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	जर ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} पर्यंत (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) स्थिर)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr शून्य name##_RB_INSERT_COLOR(संरचना name *, संरचना type *);		\
attr शून्य name##_RB_REMOVE_COLOR(संरचना name *, संरचना type *, संरचना type *);\
attr संरचना type *name##_RB_REMOVE(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_INSERT(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_FIND(संरचना name *, संरचना type *);		\
attr संरचना type *name##_RB_NFIND(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_NEXT(संरचना type *);			\
attr संरचना type *name##_RB_PREV(संरचना type *);			\
attr संरचना type *name##_RB_MINMAX(संरचना name *, पूर्णांक);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) स्थिर)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr शून्य								\
name##_RB_INSERT_COLOR(संरचना name *head, संरचना type *elm)		\
{									\
	संरचना type *parent, *gparent, *tmp;				\
	पर्यंत ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		जर (parent == RB_डावा(gparent, field)) {		\
			tmp = RB_उजवा(gparent, field);			\
			जर (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				सुरूठेवा;				\
			}						\
			जर (RB_उजवा(parent, field) == elm) {		\
				RB_ROTATE_डावा(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_उजवा(head, gparent, tmp, field);	\
		} अन्यथा {						\
			tmp = RB_डावा(gparent, field);			\
			जर (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				सुरूठेवा;				\
			}						\
			जर (RB_डावा(parent, field) == elm) {		\
				RB_ROTATE_उजवा(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_डावा(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_मूळ, field) = RB_BLACK;			\
}									\
									\
attr शून्य								\
name##_RB_REMOVE_COLOR(संरचना name *head, संरचना type *parent, संरचना type *elm) \
{									\
	संरचना type *tmp;						\
	पर्यंत ((elm == रिक्त || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_मूळ(head)) {					\
		जर (RB_डावा(parent, field) == elm) {			\
			tmp = RB_उजवा(parent, field);			\
			जर (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_डावा(head, parent, tmp, field);\
				tmp = RB_उजवा(parent, field);		\
			}						\
			जर ((RB_डावा(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_डावा(tmp, field), field) == RB_BLACK) &&\
			    (RB_उजवा(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_उजवा(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				जर (RB_उजवा(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_उजवा(tmp, field), field) == RB_BLACK) {\
					संरचना type *oleft;		\
					जर ((oleft = RB_डावा(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_उजवा(head, tmp, oleft, field);\
					tmp = RB_उजवा(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				जर (RB_उजवा(tmp, field))		\
					RB_COLOR(RB_उजवा(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_डावा(head, parent, tmp, field);\
				elm = RB_मूळ(head);			\
				थांबा;					\
			}						\
		} अन्यथा {						\
			tmp = RB_डावा(parent, field);			\
			जर (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_उजवा(head, parent, tmp, field);\
				tmp = RB_डावा(parent, field);		\
			}						\
			जर ((RB_डावा(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_डावा(tmp, field), field) == RB_BLACK) &&\
			    (RB_उजवा(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_उजवा(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				जर (RB_डावा(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_डावा(tmp, field), field) == RB_BLACK) {\
					संरचना type *oright;		\
					जर ((oright = RB_उजवा(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_डावा(head, tmp, oright, field);\
					tmp = RB_डावा(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				जर (RB_डावा(tmp, field))		\
					RB_COLOR(RB_डावा(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_उजवा(head, parent, tmp, field);\
				elm = RB_मूळ(head);			\
				थांबा;					\
			}						\
		}							\
	}								\
	जर (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr संरचना type *							\
name##_RB_REMOVE(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *child, *parent, *old = elm;			\
	पूर्णांक color;							\
	जर (RB_डावा(elm, field) == रिक्त)				\
		child = RB_उजवा(elm, field);				\
	अन्यथा जर (RB_उजवा(elm, field) == रिक्त)				\
		child = RB_डावा(elm, field);				\
	अन्यथा {								\
		संरचना type *डावा;					\
		elm = RB_उजवा(elm, field);				\
		पर्यंत ((डावा = RB_डावा(elm, field)))			\
			elm = डावा;					\
		child = RB_उजवा(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		जर (child)						\
			RB_PARENT(child, field) = parent;		\
		जर (parent) {						\
			जर (RB_डावा(parent, field) == elm)		\
				RB_डावा(parent, field) = child;		\
			अन्यथा						\
				RB_उजवा(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} अन्यथा							\
			RB_मूळ(head) = child;				\
		जर (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		जर (RB_PARENT(old, field)) {				\
			जर (RB_डावा(RB_PARENT(old, field), field) == old)\
				RB_डावा(RB_PARENT(old, field), field) = elm;\
			अन्यथा						\
				RB_उजवा(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} अन्यथा							\
			RB_मूळ(head) = elm;				\
		RB_PARENT(RB_डावा(old, field), field) = elm;		\
		जर (RB_उजवा(old, field))				\
			RB_PARENT(RB_उजवा(old, field), field) = elm;	\
		जर (parent) {						\
			डावा = parent;					\
			करा {						\
				RB_AUGMENT(डावा);			\
			} पर्यंत ((डावा = RB_PARENT(डावा, field)));	\
		}							\
		जा color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	जर (child)							\
		RB_PARENT(child, field) = parent;			\
	जर (parent) {							\
		जर (RB_डावा(parent, field) == elm)			\
			RB_डावा(parent, field) = child;			\
		अन्यथा							\
			RB_उजवा(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूळ(head) = child;					\
color:									\
	जर (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	परत (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr संरचना type *							\
name##_RB_INSERT(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp;						\
	संरचना type *parent = रिक्त;					\
	पूर्णांक comp = 0;							\
	tmp = RB_मूळ(head);						\
	पर्यंत (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		जर (comp < 0)						\
			tmp = RB_डावा(tmp, field);			\
		अन्यथा जर (comp > 0)					\
			tmp = RB_उजवा(tmp, field);			\
		अन्यथा							\
			परत (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	जर (parent != रिक्त) {						\
		जर (comp < 0)						\
			RB_डावा(parent, field) = elm;			\
		अन्यथा							\
			RB_उजवा(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूळ(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	परत (रिक्त);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr संरचना type *							\
name##_RB_FIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूळ(head);				\
	पूर्णांक comp;							\
	पर्यंत (tmp) {							\
		comp = cmp(elm, tmp);					\
		जर (comp < 0)						\
			tmp = RB_डावा(tmp, field);			\
		अन्यथा जर (comp > 0)					\
			tmp = RB_उजवा(tmp, field);			\
		अन्यथा							\
			परत (tmp);					\
	}								\
	परत (रिक्त);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr संरचना type *							\
name##_RB_NFIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूळ(head);				\
	संरचना type *res = रिक्त;					\
	पूर्णांक comp;							\
	पर्यंत (tmp) {							\
		comp = cmp(elm, tmp);					\
		जर (comp < 0) {						\
			res = tmp;					\
			tmp = RB_डावा(tmp, field);			\
		}							\
		अन्यथा जर (comp > 0)					\
			tmp = RB_उजवा(tmp, field);			\
		अन्यथा							\
			परत (tmp);					\
	}								\
	परत (res);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_NEXT(संरचना type *elm)					\
{									\
	जर (RB_उजवा(elm, field)) {					\
		elm = RB_उजवा(elm, field);				\
		पर्यंत (RB_डावा(elm, field))				\
			elm = RB_डावा(elm, field);			\
	} अन्यथा {							\
		जर (RB_PARENT(elm, field) &&				\
		    (elm == RB_डावा(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			पर्यंत (RB_PARENT(elm, field) &&			\
			    (elm == RB_उजवा(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	परत (elm);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_PREV(संरचना type *elm)					\
{									\
	जर (RB_डावा(elm, field)) {					\
		elm = RB_डावा(elm, field);				\
		पर्यंत (RB_उजवा(elm, field))				\
			elm = RB_उजवा(elm, field);			\
	} अन्यथा {							\
		जर (RB_PARENT(elm, field) &&				\
		    (elm == RB_उजवा(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			पर्यंत (RB_PARENT(elm, field) &&			\
			    (elm == RB_डावा(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	परत (elm);							\
}									\
									\
attr संरचना type *							\
name##_RB_MINMAX(संरचना name *head, पूर्णांक val)				\
{									\
	संरचना type *tmp = RB_मूळ(head);				\
	संरचना type *parent = रिक्त;					\
	पर्यंत (tmp) {							\
		parent = tmp;						\
		जर (val < 0)						\
			tmp = RB_डावा(tmp, field);			\
		अन्यथा							\
			tmp = RB_उजवा(tmp, field);			\
	}								\
	परत (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_घाला(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	साठी ((x) = RB_MIN(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	साठी ((x) = RB_MIN(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	साठी ((x) = RB_MAX(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	साठी ((x) = RB_MAX(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
