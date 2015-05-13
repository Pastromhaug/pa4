#ifndef HASHTABLE_H_
#define HASHTABLE_H_

#include "kernel.h"

extern int totalcount;
extern int totalentries;

extern int count_lock;
extern int entry_lock;

unsigned int hash( unsigned int a);

struct pair {
    int key;
    int val;
};

struct hashtable {
    struct pair* buffer;
	int TableSize;
	int numElements;
};

void hashtable_create(struct hashtable *self);

void hashtable_add(struct hashtable *self, unsigned int newkey);

void hashtable_delete(struct hashtable *self, unsigned int oldkey);

void hashtable_increment(struct hashtable *self, unsigned int check);

void hashtable_print(struct hashtable *self);

unsigned int switch_endian(unsigned int num);

#endif

