#include "kernel.h"

int evilcount = 0;
int evilentries = 0;

int evilcount_lock = 0;
int evilentry_lock = 0;

//--------------------HASHTABLE---------------------------------//
//hashtable for source addr and source ports

struct twos {
	struct twos* next;
    unsigned long key;
    int val;
};

struct evilhash {
    struct twos* buffer;
	int TableSize;
	int numElements;
};

void evilhash_create(struct evilhash *self){
	//initialize hashlist fit to 100 items
    self->TableSize= 5;
    self->numElements= 0;
    mutex_lock(&malloc_lock);
    self->buffer = (struct twos*)malloc(self->TableSize * sizeof(struct twos));
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
void evilhash_add(struct evilhash *self, unsigned long key) {
	unsigned int hashkey = (unsigned int)key % self->TableSize;
	// insert is the node that is being added
	struct twos* insert;
	struct twos* check;

	check = self->buffer[hashkey].next;
	while(check != NULL){
		if (check->key == key){
			return;
		}
		check = check->next;
	}
	mutex_lock(&malloc_lock);
	insert = (struct twos*)malloc(sizeof(struct twos));
	mutex_unlock(&malloc_lock);
	struct twos* temp;
	temp = self->buffer[hashkey].next;
	self->buffer[hashkey].next = insert;
	insert->next = temp;
	insert->key = key;
	insert->val = 0;
	self->numElements++;
	//add to total entries
	mutex_lock(&evilentry_lock);
	evilentries++;
	mutex_unlock(&evilentry_lock);
	return;
}

//Remove a saddr or destport from the hashtable
// if the value is not in the hashtable, do nothing
void evilhash_delete(struct evilhash *self, unsigned long djb2hash){
	unsigned int hashkey = djb2hash % self->TableSize;
	struct twos* check = self->buffer[hashkey].next;
	struct twos* temp = (self->buffer+hashkey);
	while(check != NULL) {
		if (check->key == djb2hash){
			//decrease total entry by 1
			mutex_lock(&evilentry_lock);
			evilentries--;
			mutex_unlock(&evilentry_lock);

			//decrease total count by val
			mutex_lock(&evilcount_lock);
			evilcount = evilcount - check->val;
			mutex_unlock(&evilcount_lock);

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
void evilhash_increment(struct evilhash *self, unsigned long djb2hash){
	unsigned int hashkey = djb2hash % self->TableSize;
	struct twos* temp = self->buffer[hashkey].next;
	while(temp != NULL) {
		//unsigned long temp2 = switch_endian(djb2hash);
		unsigned long temp3 = switch_endian(temp->key);
		
		if (temp3 == djb2hash){
			
			temp->val++;
			
			//increase total count by 1
			mutex_lock(&evilcount_lock);
			evilcount++;
			mutex_unlock(&evilcount_lock);
		}
		temp = temp->next;
	} 
	return;
}

void evilhash_print(struct evilhash *self){
	//Print out the statistics
	struct twos* printtemp;
	unsigned long addr;
	printf("count      evil_source\n");
	for (int k=0; k < self->TableSize; k++){
		printtemp = self->buffer[k].next;
	  	while(printtemp != NULL){
	  		addr = switch_endian(printtemp->key);
	      	printf("%3d        0x%08lx      |\n", printtemp->val, addr);
	     	printtemp = printtemp->next;
	    }
	}
	printf("total evil count:        %d\n", evilcount);
	printf("total evil entries:      %d\n\n", evilentries);

	double seconds = ((double)current_cpu_cycles())/((double)1000000);
	printf("[net: total packets :  %d  (%f pkts/sec since last print)]\n", total_pkts, ((double)total_pkts)/seconds);
	printf("[net: total bytes :  %d  (%f Mbit/sec since last print)]\n", total_bytes, ((((double)total_bytes)*8)/1000000)/seconds);
	
}




