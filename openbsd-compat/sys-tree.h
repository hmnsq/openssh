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

#समावेश "config.h"
#अगर_घोषित NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#पूर्ण_अगर

#अगर_अघोषित	SYS_वृक्ष_H
#घोषणा	SYS_वृक्ष_H

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

#घोषणा SPLAY_शीर्ष(name, type)						\
काष्ठा name {								\
	काष्ठा type *sph_मूल; /* root of the tree */			\
}

#घोषणा SPLAY_INITIALIZER(मूल)						\
	{ शून्य }

#घोषणा SPLAY_INIT(मूल) करो {						\
	(मूल)->sph_मूल = शून्य;					\
} जबतक (0)

#घोषणा SPLAY_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *spe_बायाँ; /* left element */			\
	काष्ठा type *spe_दायाँ; /* right element */			\
}

#घोषणा SPLAY_बायाँ(elm, field)		(elm)->field.spe_बायाँ
#घोषणा SPLAY_दायाँ(elm, field)		(elm)->field.spe_दायाँ
#घोषणा SPLAY_मूल(शीर्ष_2)		(शीर्ष_2)->sph_मूल
#घोषणा SPLAY_EMPTY(शीर्ष_2)		(SPLAY_मूल(शीर्ष_2) == शून्य)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#घोषणा SPLAY_ROTATE_दायाँ(शीर्ष_2, tmp, field) करो {			\
	SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) = SPLAY_दायाँ(tmp, field);	\
	SPLAY_दायाँ(tmp, field) = (शीर्ष_2)->sph_मूल;			\
	(शीर्ष_2)->sph_मूल = tmp;						\
} जबतक (0)
	
#घोषणा SPLAY_ROTATE_बायाँ(शीर्ष_2, tmp, field) करो {			\
	SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) = SPLAY_बायाँ(tmp, field);	\
	SPLAY_बायाँ(tmp, field) = (शीर्ष_2)->sph_मूल;			\
	(शीर्ष_2)->sph_मूल = tmp;						\
} जबतक (0)

#घोषणा SPLAY_LINKLEFT(शीर्ष_2, tmp, field) करो {				\
	SPLAY_बायाँ(tmp, field) = (शीर्ष_2)->sph_मूल;			\
	tmp = (शीर्ष_2)->sph_मूल;						\
	(शीर्ष_2)->sph_मूल = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);		\
} जबतक (0)

#घोषणा SPLAY_LINKRIGHT(शीर्ष_2, tmp, field) करो {				\
	SPLAY_दायाँ(tmp, field) = (शीर्ष_2)->sph_मूल;			\
	tmp = (शीर्ष_2)->sph_मूल;						\
	(शीर्ष_2)->sph_मूल = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);	\
} जबतक (0)

#घोषणा SPLAY_ASSEMBLE(शीर्ष_2, गाँठ, बायाँ, दायाँ, field) करो {		\
	SPLAY_दायाँ(बायाँ, field) = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);	\
	SPLAY_बायाँ(दायाँ, field) = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);\
	SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) = SPLAY_दायाँ(गाँठ, field);	\
	SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) = SPLAY_बायाँ(गाँठ, field);	\
} जबतक (0)

/* Generates prototypes and inline functions */

#घोषणा SPLAY_PROTOTYPE(name, type, field, cmp)				\
व्योम name##_SPLAY(काष्ठा name *, काष्ठा type *);			\
व्योम name##_SPLAY_MINMAX(काष्ठा name *, पूर्णांक);				\
काष्ठा type *name##_SPLAY_INSERT(काष्ठा name *, काष्ठा type *);		\
काष्ठा type *name##_SPLAY_REMOVE(काष्ठा name *, काष्ठा type *);		\
									\
/* Finds the node with the same key as elm */				\
अटल __inline काष्ठा type *						\
name##_SPLAY_FIND(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	अगर (SPLAY_EMPTY(शीर्ष_2))						\
		वापस(शून्य);						\
	name##_SPLAY(शीर्ष_2, elm);					\
	अगर ((cmp)(elm, (शीर्ष_2)->sph_मूल) == 0)				\
		वापस (शीर्ष_2->sph_मूल);				\
	वापस (शून्य);							\
}									\
									\
अटल __inline काष्ठा type *						\
name##_SPLAY_NEXT(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	name##_SPLAY(शीर्ष_2, elm);					\
	अगर (SPLAY_दायाँ(elm, field) != शून्य) {				\
		elm = SPLAY_दायाँ(elm, field);				\
		जबतक (SPLAY_बायाँ(elm, field) != शून्य) {		\
			elm = SPLAY_बायाँ(elm, field);			\
		}							\
	} अन्यथा								\
		elm = शून्य;						\
	वापस (elm);							\
}									\
									\
अटल __inline काष्ठा type *						\
name##_SPLAY_MIN_MAX(काष्ठा name *शीर्ष_2, पूर्णांक val)			\
{									\
	name##_SPLAY_MINMAX(शीर्ष_2, val);					\
        वापस (SPLAY_मूल(शीर्ष_2));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#घोषणा SPLAY_GENERATE(name, type, field, cmp)				\
काष्ठा type *								\
name##_SPLAY_INSERT(काष्ठा name *शीर्ष_2, काष्ठा type *elm)		\
{									\
    अगर (SPLAY_EMPTY(शीर्ष_2)) {						\
	    SPLAY_बायाँ(elm, field) = SPLAY_दायाँ(elm, field) = शून्य;	\
    } अन्यथा {								\
	    पूर्णांक __comp;							\
	    name##_SPLAY(शीर्ष_2, elm);					\
	    __comp = (cmp)(elm, (शीर्ष_2)->sph_मूल);			\
	    अगर(__comp < 0) {						\
		    SPLAY_बायाँ(elm, field) = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);\
		    SPLAY_दायाँ(elm, field) = (शीर्ष_2)->sph_मूल;		\
		    SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) = शून्य;		\
	    } अन्यथा अगर (__comp > 0) {					\
		    SPLAY_दायाँ(elm, field) = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);\
		    SPLAY_बायाँ(elm, field) = (शीर्ष_2)->sph_मूल;		\
		    SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) = शून्य;	\
	    } अन्यथा							\
		    वापस ((शीर्ष_2)->sph_मूल);				\
    }									\
    (शीर्ष_2)->sph_मूल = (elm);						\
    वापस (शून्य);							\
}									\
									\
काष्ठा type *								\
name##_SPLAY_REMOVE(काष्ठा name *शीर्ष_2, काष्ठा type *elm)		\
{									\
	काष्ठा type *__tmp;						\
	अगर (SPLAY_EMPTY(शीर्ष_2))						\
		वापस (शून्य);						\
	name##_SPLAY(शीर्ष_2, elm);					\
	अगर ((cmp)(elm, (शीर्ष_2)->sph_मूल) == 0) {			\
		अगर (SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) == शून्य) {	\
			(शीर्ष_2)->sph_मूल = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);\
		} अन्यथा {						\
			__tmp = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);	\
			(शीर्ष_2)->sph_मूल = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);\
			name##_SPLAY(शीर्ष_2, elm);			\
			SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) = __tmp;	\
		}							\
		वापस (elm);						\
	}								\
	वापस (शून्य);							\
}									\
									\
व्योम									\
name##_SPLAY(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	काष्ठा type __node, *__left, *__right, *__tmp;			\
	पूर्णांक __comp;							\
\
	SPLAY_बायाँ(&__node, field) = SPLAY_दायाँ(&__node, field) = शून्य;\
	__left = __right = &__node;					\
\
	जबतक ((__comp = (cmp)(elm, (शीर्ष_2)->sph_मूल))) {		\
		अगर (__comp < 0) {					\
			__tmp = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);	\
			अगर (__tmp == शून्य)				\
				अवरोध;					\
			अगर ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_दायाँ(शीर्ष_2, __tmp, field);	\
				अगर (SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) == शून्य)\
					अवरोध;				\
			}						\
			SPLAY_LINKLEFT(शीर्ष_2, __right, field);		\
		} अन्यथा अगर (__comp > 0) {				\
			__tmp = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);	\
			अगर (__tmp == शून्य)				\
				अवरोध;					\
			अगर ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_बायाँ(शीर्ष_2, __tmp, field);	\
				अगर (SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) == शून्य)\
					अवरोध;				\
			}						\
			SPLAY_LINKRIGHT(शीर्ष_2, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(शीर्ष_2, &__node, __left, __right, field);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
व्योम name##_SPLAY_MINMAX(काष्ठा name *शीर्ष_2, पूर्णांक __comp) \
{									\
	काष्ठा type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_बायाँ(&__node, field) = SPLAY_दायाँ(&__node, field) = शून्य;\
	__left = __right = &__node;					\
\
	जबतक (1) {							\
		अगर (__comp < 0) {					\
			__tmp = SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field);	\
			अगर (__tmp == शून्य)				\
				अवरोध;					\
			अगर (__comp < 0){				\
				SPLAY_ROTATE_दायाँ(शीर्ष_2, __tmp, field);	\
				अगर (SPLAY_बायाँ((शीर्ष_2)->sph_मूल, field) == शून्य)\
					अवरोध;				\
			}						\
			SPLAY_LINKLEFT(शीर्ष_2, __right, field);		\
		} अन्यथा अगर (__comp > 0) {				\
			__tmp = SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field);	\
			अगर (__tmp == शून्य)				\
				अवरोध;					\
			अगर (__comp > 0) {				\
				SPLAY_ROTATE_बायाँ(शीर्ष_2, __tmp, field);	\
				अगर (SPLAY_दायाँ((शीर्ष_2)->sph_मूल, field) == शून्य)\
					अवरोध;				\
			}						\
			SPLAY_LINKRIGHT(शीर्ष_2, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(शीर्ष_2, &__node, __left, __right, field);		\
}

#घोषणा SPLAY_NEGINF	-1
#घोषणा SPLAY_INF	1

#घोषणा SPLAY_जोड़ो(name, x, y)	name##_SPLAY_INSERT(x, y)
#घोषणा SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#घोषणा SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#घोषणा SPLAY_अग्र(name, x, y)		name##_SPLAY_NEXT(x, y)
#घोषणा SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? शून्य	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#घोषणा SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? शून्य	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#घोषणा SPLAY_FOREACH(x, name, शीर्ष_2)					\
	क्रम ((x) = SPLAY_MIN(name, शीर्ष_2);				\
	     (x) != शून्य;						\
	     (x) = SPLAY_अग्र(name, शीर्ष_2, x))

/* Macros that define a red-black tree */
#घोषणा RB_शीर्ष(name, type)						\
काष्ठा name {								\
	काष्ठा type *rbh_मूल; /* root of the tree */			\
}

#घोषणा RB_INITIALIZER(मूल)						\
	{ शून्य }

#घोषणा RB_INIT(मूल) करो {						\
	(मूल)->rbh_मूल = शून्य;					\
} जबतक (0)

#घोषणा RB_BLACK	0
#घोषणा RB_RED		1
#घोषणा RB_ENTRY(type)							\
काष्ठा {								\
	काष्ठा type *rbe_बायाँ;		/* left element */		\
	काष्ठा type *rbe_दायाँ;		/* right element */		\
	काष्ठा type *rbe_parent;	/* parent element */		\
	पूर्णांक rbe_color;			/* node color */		\
}

#घोषणा RB_बायाँ(elm, field)		(elm)->field.rbe_बायाँ
#घोषणा RB_दायाँ(elm, field)		(elm)->field.rbe_दायाँ
#घोषणा RB_PARENT(elm, field)		(elm)->field.rbe_parent
#घोषणा RB_COLOR(elm, field)		(elm)->field.rbe_color
#घोषणा RB_मूल(शीर्ष_2)			(शीर्ष_2)->rbh_मूल
#घोषणा RB_EMPTY(शीर्ष_2)			(RB_मूल(शीर्ष_2) == शून्य)

#घोषणा RB_SET(elm, parent, field) करो {					\
	RB_PARENT(elm, field) = parent;					\
	RB_बायाँ(elm, field) = RB_दायाँ(elm, field) = शून्य;		\
	RB_COLOR(elm, field) = RB_RED;					\
} जबतक (0)

#घोषणा RB_SET_BLACKRED(black, red, field) करो {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} जबतक (0)

#अगर_अघोषित RB_AUGMENT
#घोषणा RB_AUGMENT(x)	करो {} जबतक (0)
#पूर्ण_अगर

#घोषणा RB_ROTATE_बायाँ(शीर्ष_2, elm, tmp, field) करो {			\
	(tmp) = RB_दायाँ(elm, field);					\
	अगर ((RB_दायाँ(elm, field) = RB_बायाँ(tmp, field))) {		\
		RB_PARENT(RB_बायाँ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	अगर ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		अगर ((elm) == RB_बायाँ(RB_PARENT(elm, field), field))	\
			RB_बायाँ(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_दायाँ(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(शीर्ष_2)->rbh_मूल = (tmp);				\
	RB_बायाँ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	अगर ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} जबतक (0)

#घोषणा RB_ROTATE_दायाँ(शीर्ष_2, elm, tmp, field) करो {			\
	(tmp) = RB_बायाँ(elm, field);					\
	अगर ((RB_बायाँ(elm, field) = RB_दायाँ(tmp, field))) {		\
		RB_PARENT(RB_दायाँ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	अगर ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		अगर ((elm) == RB_बायाँ(RB_PARENT(elm, field), field))	\
			RB_बायाँ(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_दायाँ(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(शीर्ष_2)->rbh_मूल = (tmp);				\
	RB_दायाँ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	अगर ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} जबतक (0)

/* Generates prototypes and inline functions */
#घोषणा	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#घोषणा	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) अटल)
#घोषणा RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr व्योम name##_RB_INSERT_COLOR(काष्ठा name *, काष्ठा type *);		\
attr व्योम name##_RB_REMOVE_COLOR(काष्ठा name *, काष्ठा type *, काष्ठा type *);\
attr काष्ठा type *name##_RB_REMOVE(काष्ठा name *, काष्ठा type *);	\
attr काष्ठा type *name##_RB_INSERT(काष्ठा name *, काष्ठा type *);	\
attr काष्ठा type *name##_RB_FIND(काष्ठा name *, काष्ठा type *);		\
attr काष्ठा type *name##_RB_NFIND(काष्ठा name *, काष्ठा type *);	\
attr काष्ठा type *name##_RB_NEXT(काष्ठा type *);			\
attr काष्ठा type *name##_RB_PREV(काष्ठा type *);			\
attr काष्ठा type *name##_RB_MINMAX(काष्ठा name *, पूर्णांक);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#घोषणा	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#घोषणा	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) अटल)
#घोषणा RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr व्योम								\
name##_RB_INSERT_COLOR(काष्ठा name *शीर्ष_2, काष्ठा type *elm)		\
{									\
	काष्ठा type *parent, *gparent, *tmp;				\
	जबतक ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		अगर (parent == RB_बायाँ(gparent, field)) {		\
			tmp = RB_दायाँ(gparent, field);			\
			अगर (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				जारी;				\
			}						\
			अगर (RB_दायाँ(parent, field) == elm) {		\
				RB_ROTATE_बायाँ(शीर्ष_2, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_दायाँ(शीर्ष_2, gparent, tmp, field);	\
		} अन्यथा {						\
			tmp = RB_बायाँ(gparent, field);			\
			अगर (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				जारी;				\
			}						\
			अगर (RB_बायाँ(parent, field) == elm) {		\
				RB_ROTATE_दायाँ(शीर्ष_2, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_बायाँ(शीर्ष_2, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(शीर्ष_2->rbh_मूल, field) = RB_BLACK;			\
}									\
									\
attr व्योम								\
name##_RB_REMOVE_COLOR(काष्ठा name *शीर्ष_2, काष्ठा type *parent, काष्ठा type *elm) \
{									\
	काष्ठा type *tmp;						\
	जबतक ((elm == शून्य || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_मूल(शीर्ष_2)) {					\
		अगर (RB_बायाँ(parent, field) == elm) {			\
			tmp = RB_दायाँ(parent, field);			\
			अगर (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_बायाँ(शीर्ष_2, parent, tmp, field);\
				tmp = RB_दायाँ(parent, field);		\
			}						\
			अगर ((RB_बायाँ(tmp, field) == शून्य ||		\
			    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) &&\
			    (RB_दायाँ(tmp, field) == शून्य ||		\
			    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				अगर (RB_दायाँ(tmp, field) == शून्य ||	\
				    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK) {\
					काष्ठा type *oleft;		\
					अगर ((oleft = RB_बायाँ(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_दायाँ(शीर्ष_2, tmp, oleft, field);\
					tmp = RB_दायाँ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				अगर (RB_दायाँ(tmp, field))		\
					RB_COLOR(RB_दायाँ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_बायाँ(शीर्ष_2, parent, tmp, field);\
				elm = RB_मूल(शीर्ष_2);			\
				अवरोध;					\
			}						\
		} अन्यथा {						\
			tmp = RB_बायाँ(parent, field);			\
			अगर (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_दायाँ(शीर्ष_2, parent, tmp, field);\
				tmp = RB_बायाँ(parent, field);		\
			}						\
			अगर ((RB_बायाँ(tmp, field) == शून्य ||		\
			    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) &&\
			    (RB_दायाँ(tmp, field) == शून्य ||		\
			    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				अगर (RB_बायाँ(tmp, field) == शून्य ||	\
				    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) {\
					काष्ठा type *oright;		\
					अगर ((oright = RB_दायाँ(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_बायाँ(शीर्ष_2, tmp, oright, field);\
					tmp = RB_बायाँ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				अगर (RB_बायाँ(tmp, field))		\
					RB_COLOR(RB_बायाँ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_दायाँ(शीर्ष_2, parent, tmp, field);\
				elm = RB_मूल(शीर्ष_2);			\
				अवरोध;					\
			}						\
		}							\
	}								\
	अगर (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr काष्ठा type *							\
name##_RB_REMOVE(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	काष्ठा type *child, *parent, *old = elm;			\
	पूर्णांक color;							\
	अगर (RB_बायाँ(elm, field) == शून्य)				\
		child = RB_दायाँ(elm, field);				\
	अन्यथा अगर (RB_दायाँ(elm, field) == शून्य)				\
		child = RB_बायाँ(elm, field);				\
	अन्यथा {								\
		काष्ठा type *बायाँ;					\
		elm = RB_दायाँ(elm, field);				\
		जबतक ((बायाँ = RB_बायाँ(elm, field)))			\
			elm = बायाँ;					\
		child = RB_दायाँ(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		अगर (child)						\
			RB_PARENT(child, field) = parent;		\
		अगर (parent) {						\
			अगर (RB_बायाँ(parent, field) == elm)		\
				RB_बायाँ(parent, field) = child;		\
			अन्यथा						\
				RB_दायाँ(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} अन्यथा							\
			RB_मूल(शीर्ष_2) = child;				\
		अगर (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		अगर (RB_PARENT(old, field)) {				\
			अगर (RB_बायाँ(RB_PARENT(old, field), field) == old)\
				RB_बायाँ(RB_PARENT(old, field), field) = elm;\
			अन्यथा						\
				RB_दायाँ(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} अन्यथा							\
			RB_मूल(शीर्ष_2) = elm;				\
		RB_PARENT(RB_बायाँ(old, field), field) = elm;		\
		अगर (RB_दायाँ(old, field))				\
			RB_PARENT(RB_दायाँ(old, field), field) = elm;	\
		अगर (parent) {						\
			बायाँ = parent;					\
			करो {						\
				RB_AUGMENT(बायाँ);			\
			} जबतक ((बायाँ = RB_PARENT(बायाँ, field)));	\
		}							\
		जाओ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	अगर (child)							\
		RB_PARENT(child, field) = parent;			\
	अगर (parent) {							\
		अगर (RB_बायाँ(parent, field) == elm)			\
			RB_बायाँ(parent, field) = child;			\
		अन्यथा							\
			RB_दायाँ(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूल(शीर्ष_2) = child;					\
color:									\
	अगर (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(शीर्ष_2, parent, child);		\
	वापस (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr काष्ठा type *							\
name##_RB_INSERT(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	काष्ठा type *tmp;						\
	काष्ठा type *parent = शून्य;					\
	पूर्णांक comp = 0;							\
	tmp = RB_मूल(शीर्ष_2);						\
	जबतक (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		अगर (comp < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा अगर (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			वापस (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	अगर (parent != शून्य) {						\
		अगर (comp < 0)						\
			RB_बायाँ(parent, field) = elm;			\
		अन्यथा							\
			RB_दायाँ(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_मूल(शीर्ष_2) = elm;					\
	name##_RB_INSERT_COLOR(शीर्ष_2, elm);				\
	वापस (शून्य);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr काष्ठा type *							\
name##_RB_FIND(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	काष्ठा type *tmp = RB_मूल(शीर्ष_2);				\
	पूर्णांक comp;							\
	जबतक (tmp) {							\
		comp = cmp(elm, tmp);					\
		अगर (comp < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा अगर (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			वापस (tmp);					\
	}								\
	वापस (शून्य);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr काष्ठा type *							\
name##_RB_NFIND(काष्ठा name *शीर्ष_2, काष्ठा type *elm)			\
{									\
	काष्ठा type *tmp = RB_मूल(शीर्ष_2);				\
	काष्ठा type *res = शून्य;					\
	पूर्णांक comp;							\
	जबतक (tmp) {							\
		comp = cmp(elm, tmp);					\
		अगर (comp < 0) {						\
			res = tmp;					\
			tmp = RB_बायाँ(tmp, field);			\
		}							\
		अन्यथा अगर (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			वापस (tmp);					\
	}								\
	वापस (res);							\
}									\
									\
/* ARGSUSED */								\
attr काष्ठा type *							\
name##_RB_NEXT(काष्ठा type *elm)					\
{									\
	अगर (RB_दायाँ(elm, field)) {					\
		elm = RB_दायाँ(elm, field);				\
		जबतक (RB_बायाँ(elm, field))				\
			elm = RB_बायाँ(elm, field);			\
	} अन्यथा {							\
		अगर (RB_PARENT(elm, field) &&				\
		    (elm == RB_बायाँ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			जबतक (RB_PARENT(elm, field) &&			\
			    (elm == RB_दायाँ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	वापस (elm);							\
}									\
									\
/* ARGSUSED */								\
attr काष्ठा type *							\
name##_RB_PREV(काष्ठा type *elm)					\
{									\
	अगर (RB_बायाँ(elm, field)) {					\
		elm = RB_बायाँ(elm, field);				\
		जबतक (RB_दायाँ(elm, field))				\
			elm = RB_दायाँ(elm, field);			\
	} अन्यथा {							\
		अगर (RB_PARENT(elm, field) &&				\
		    (elm == RB_दायाँ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			जबतक (RB_PARENT(elm, field) &&			\
			    (elm == RB_बायाँ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	वापस (elm);							\
}									\
									\
attr काष्ठा type *							\
name##_RB_MINMAX(काष्ठा name *शीर्ष_2, पूर्णांक val)				\
{									\
	काष्ठा type *tmp = RB_मूल(शीर्ष_2);				\
	काष्ठा type *parent = शून्य;					\
	जबतक (tmp) {							\
		parent = tmp;						\
		अगर (val < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा							\
			tmp = RB_दायाँ(tmp, field);			\
	}								\
	वापस (parent);						\
}

#घोषणा RB_NEGINF	-1
#घोषणा RB_INF	1

#घोषणा RB_जोड़ो(name, x, y)	name##_RB_INSERT(x, y)
#घोषणा RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#घोषणा RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#घोषणा RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#घोषणा RB_अग्र(name, x, y)	name##_RB_NEXT(y)
#घोषणा RB_पूर्व(name, x, y)	name##_RB_PREV(y)
#घोषणा RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#घोषणा RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#घोषणा RB_FOREACH(x, name, शीर्ष_2)					\
	क्रम ((x) = RB_MIN(name, शीर्ष_2);					\
	     (x) != शून्य;						\
	     (x) = name##_RB_NEXT(x))

#घोषणा RB_FOREACH_SAFE(x, name, शीर्ष_2, y)				\
	क्रम ((x) = RB_MIN(name, शीर्ष_2);					\
	    ((x) != शून्य) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#घोषणा RB_FOREACH_REVERSE(x, name, शीर्ष_2)				\
	क्रम ((x) = RB_MAX(name, शीर्ष_2);					\
	     (x) != शून्य;						\
	     (x) = name##_RB_PREV(x))

#घोषणा RB_FOREACH_REVERSE_SAFE(x, name, शीर्ष_2, y)			\
	क्रम ((x) = RB_MAX(name, शीर्ष_2);					\
	    ((x) != शून्य) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#पूर्ण_अगर	/* _SYS_TREE_H_ */
