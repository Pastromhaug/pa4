#ifndef VULNHASH_H_
#define VULNHASH_H_

#include "kernel.h"

extern int vulncount;
extern int vulnentries;

extern int vulncount_lock;
extern int vulnentry_lock;

unsigned int hash( unsigned int a);

struct couple {
    int key;
    int val;
};

struct vulnhash {
    struct couple* buffer;
	int TableSize;
	int numElements;
};

void vulnhash_create(struct vulnhash *self);

void vulnhash_add(struct vulnhash *self, unsigned int newkey);

void vulnhash_delete(struct vulnhash *self, unsigned int oldkey);

void vulnhash_increment(struct vulnhash *self, unsigned int check);

void vulnhash_print(struct vulnhash *self);


#endif

