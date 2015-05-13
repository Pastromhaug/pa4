#include "kernel.h"

//--------------------HASHTABLE---------------------------------//
//hashtable for source addr and source ports

unsigned int hash( unsigned int a) {
    a = (a ^ 61) ^ (a >>16);
    a = a + (a <<3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

struct pair {
    int key;
    int val;
};

struct hashtable {
    struct pair* buffer;
	int TableSize;
	int numElements;
};

void hashtable_create(struct hashtable *self){
	//initialize hashlist fit to 100 items
    self->TableSize= 50;
    self->numElements= 0;
    self->buffer = (struct pair*)malloc(self->TableSize * sizeof(struct pair));
    // initialize each key and val to 0
    for (int i = 0; i< self->TableSize; i++){
    	self->buffer[i].key = 0;
    	self->buffer[i].val = 0;
    }
}

// add a value as key to the hashtable and initialize val to 0
// if that value is already in the hashtable, do nothing
void hashtable_add(struct hashtable *self, unsigned int newkey) {
	unsigned int hashkey = hash(newkey) % self->TableSize;
	if(self->buffer[hashkey].key == 0)
	{
		self->buffer[hashkey].key = newkey;
		self->numElements++;
		//printf("added\n");
	}
	return;
}

//Remove a saddr or destport from the hashtable
// if the value is not in the hashtable, do nothing
void hashtable_delete(struct hashtable *self, unsigned int oldkey){
	unsigned int hashkey = hash(oldkey) % self->TableSize;
	if(self->buffer[hashkey].key != 0)
	{
		self->buffer[hashkey].key = 0;
		self->buffer[hashkey].val = 0;
		self->numElements--;
		//printf("deleted\n");
	}
	return;
}

// check if a saddr or destport is in the hashtable, if so, increment the value by 1
void hashtable_increment(struct hashtable *self, unsigned int check){
	unsigned int hashkey = hash(check) % self->TableSize;
	//printf("key is %d\n", self->buffer[hashkey].key);
	if (self->buffer[hashkey].key != 0){
		self->buffer[hashkey].val++;
		//printf("number is %d\n", self->buffer[hashkey].val);
	}
	return;
}



