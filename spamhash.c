#include "kernel.h"

int spamcount = 0;
int spamentries = 0;

int spamcount_lock = 0;
int spamentry_lock = 0;

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
	struct pair* next;
    int key;
    int val;
};

struct spamhash {
    struct pair* buffer;
	int TableSize;
	int numElements;
};

void spamhash_create(struct spamhash *self){
	//initialize hashlist fit to 100 items
    self->TableSize= 5;
    self->numElements= 0;
    mutex_lock(&malloc_lock);
    self->buffer = (struct pair*)malloc(self->TableSize * sizeof(struct pair));
    mutex_unlock(&malloc_lock);
    // initialize each key and val to 0
    for (int i = 0; i< self->TableSize; i++){
    	self->buffer[i].next = NULL;
    	self->buffer[i].key = 0;
    	self->buffer[i].val = 0;
    }
}

// add a value as key to the hashtable and initialize val to 0
// if that value is already in the hashtable, do nothing
void spamhash_add(struct spamhash *self, unsigned int newkey) {
	unsigned int hashkey = hash(newkey) % self->TableSize;

	// insert is the node that is being added
	struct pair* insert;
	struct pair* check;
	check = self->buffer[hashkey].next;
	while(check != NULL){
		if (check->key == newkey){
			return;
		}
		check = check->next;
	}
	mutex_lock(&malloc_lock);
	insert = (struct pair*)malloc(sizeof(struct pair));
	mutex_unlock(&malloc_lock);
	struct pair* temp;
	temp = self->buffer[hashkey].next;
	self->buffer[hashkey].next = insert;
	insert->next = temp;
	insert->key = newkey;
	insert->val = 0;
	self->numElements++;
	//add to total entries
	mutex_lock(&spamentry_lock);
	spamentries++;
	mutex_unlock(&spamentry_lock);
	return;
}

//Remove a saddr or destport from the hashtable
// if the value is not in the hashtable, do nothing
void spamhash_delete(struct spamhash *self, unsigned int oldkey){
	unsigned int hashkey = hash(oldkey) % self->TableSize;
	struct pair* check = self->buffer[hashkey].next;
	struct pair* temp = (self->buffer+hashkey);

	while(check != NULL) {
		if (check->key == oldkey){
			//decrease total entry by 1
			mutex_lock(&spamentry_lock);
			spamentries--;
			mutex_unlock(&spamentry_lock);

			//decrease total count by val
			mutex_lock(&spamcount_lock);
			spamcount = spamcount - check->val;
			mutex_unlock(&spamcount_lock);

			temp->next = check->next;
			mutex_lock(&free_lock);
			free(check);
			mutex_unlock(&free_lock);
		} 
		check = check->next;
		temp = temp->next;
	}
	return;
}

// check if a saddr or destport is in the hashtable, if so, increment the value by 1
void spamhash_increment(struct spamhash *self, unsigned int check){
	unsigned int hashkey = hash(check) % self->TableSize;
	struct pair* temp = self->buffer[hashkey].next;
	while(temp != NULL) {
		if (temp->key == check){
			temp->val++;

			//increase total count by 1
			mutex_lock(&spamcount_lock);
			spamcount++;
			mutex_unlock(&spamcount_lock);
		}
		temp = temp->next;
	} 
	return;
}

void spamhash_print(struct spamhash *self){
	//Print out the statistics
	struct pair* printtemp;
	unsigned int addr;
	printf("print statistics\n");
	printf("count      spam_source\n");
	for (int k=0; k < self->TableSize; k++){
		printtemp = self->buffer[k].next;
	  	while(printtemp != NULL){
	  		addr = switch_endian(printtemp->key);
	      	printf("%3d        0x%08x      |\n", printtemp->val, addr);
	     	printtemp = printtemp->next;
	    }
	}
	printf("total spam count:        %d\n", spamcount);
	printf("total spam entries:      %d\n", spamentries);
}




