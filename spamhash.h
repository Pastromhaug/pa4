#ifndef SPAMHASH_H_
#define SPAMHASH_H_

#include "kernel.h"

extern int spamcount;
extern int spamentries;

extern int count_lock;
extern int entry_lock;

unsigned int hash( unsigned int a);

struct pair {
    int key;
    int val;
};

struct spamhash {
    struct pair* buffer;
	int TableSize;
	int numElements;
};

void spamhash_create(struct spamhash *self);

void spamhash_add(struct spamhash *self, unsigned int newkey);

void spamhash_delete(struct spamhash *self, unsigned int oldkey);

void spamhash_increment(struct spamhash *self, unsigned int check);

void spamhash_print(struct spamhash *self);


#endif

