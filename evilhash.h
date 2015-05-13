#ifndef EVILHASH_H_
#define EVILHASH_H_

#include "kernel.h"

extern int evilcount;
extern int evilentries;

extern int evilcount_lock;
extern int evilentry_lock;

struct twos {
    int key;
    int val;
};

struct evilhash {
    struct twos* buffer;
	int TableSize;
	int numElements;
};

void evilhash_create(struct evilhash *self);

void evilhash_add(struct evilhash *self, unsigned int newkey);

void evilhash_delete(struct evilhash *self, unsigned int oldkey);

void evilhash_increment(struct evilhash *self, unsigned int check);

void evilhash_print(struct evilhash *self);


#endif

