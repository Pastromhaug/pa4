#include "kernel.h"

int vulncount = 0;
int vulnentries = 0;

int vulncount_lock = 0;
int vulnentry_lock = 0;

//--------------------HASHTABLE---------------------------------//
//hashtable for source addr and source ports

unsigned int hash2(unsigned short a) {

    a = (a ^ 61) ^ (a >>16);
    a = a + (a <<3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

struct couple {
	struct couple* next;
    short key;
    int val;
};

struct vulnhash {
    struct couple* buffer;
	int TableSize;
	int numElements;
};

void vulnhash_create(struct vulnhash *self){
	//initialize hashlist fit to 100 items
    self->TableSize= 5;
    self->numElements= 0;
    mutex_lock(&malloc_lock);
    self->buffer = (struct couple*)malloc(self->TableSize * sizeof(struct couple));
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
void vulnhash_add(struct vulnhash *self, unsigned short newkey) {
	//printf("TableSize is %d\n", self->TableSize);
	unsigned int hashkey = hash2(newkey) % self->TableSize;
	//struct couple** temp = &(self->buffer + hashkey);
	//printf("temp is %p\n", temp);

	// insert is the node that is being added
	struct couple* insert;
	// temp is temporary node to keep track of next
	

	struct couple* check;

//	if(self->buffer[hashkey].key == 0){
//		self->buffer[hashkey].key = newkey;
//		self->buffer[hashkey].val = 0;
//		self->buffer[hashkey].next = NULL;
//		self->numElements++;
//		printf("hashkey: %d, key: %d, val: %d\n", hashkey, self->buffer[hashkey].key, self->buffer[hashkey].val);
//	} else {
		//check if the other nodes contain newkey
		check = self->buffer[hashkey].next;
		while(check != NULL){
			if (check->key == newkey){
				return;
			}
			check = check->next;
		}

		mutex_lock(&malloc_lock);
		insert = (struct couple*)malloc(sizeof(struct couple));
		mutex_unlock(&malloc_lock);



		struct couple* temp;
		temp = self->buffer[hashkey].next;
		self->buffer[hashkey].next = insert;
		insert->next = temp;
		insert->key = newkey;
		insert->val = 0;
		self->numElements++;

		//add to total entries
		mutex_lock(&vulnentry_lock);
		vulnentries++;
		mutex_unlock(&vulnentry_lock);

		//printf("hashkey: %d, key: %08x, val: %d\n", hashkey, insert->key, insert->val);

//	}



	//int i = 1;
	//while(temp != NULL) {
//		printf("do not print\n");
//		printf("hashkey: %d, bucket# %d, key: %d, val: %d\n", hashkey, i, temp->key, temp->val);
//		if (temp->key == newkey) return;
//		temp = temp->next;
//		i++;
//	} 
	//if (temp->key == newkey) return;
//	mutex_lock(&malloc_lock);
//	temp = (struct couple*)malloc(sizeof(struct couple));
//	mutex_unlock(&malloc_lock);
//	temp->next = NULL;
//	temp->key = newkey;
//	temp->val = 0;
//	self->numElements++;
//	printf("hashkey: %d, bucket# %d, key: %d, val: %d\n", hashkey, i, temp->key, temp->val);
	/*printf("added\n");
	printf("temp is %p\n", temp);
	printf("the newkey is %d\n", newkey);*/
	return;
}

//Remove a saddr or destport from the hashtable
// if the value is not in the hashtable, do nothing
void vulnhash_delete(struct vulnhash *self, unsigned short oldkey){
	/*unsigned int hashkey = hash2(oldkey) % self->TableSize;
	if(self->buffer[hashkey].key != 0)
	{
		self->buffer[hashkey].key = 0;
		self->buffer[hashkey].val = 0;
		self->numElements--;
		//printf("deleted\n");
	}*/

	unsigned int hashkey = hash2(oldkey) % self->TableSize;
	struct couple* check = self->buffer[hashkey].next;
	struct couple* temp = (self->buffer+hashkey);
	//printf("trying to delete %08x\n", oldkey);


	while(check != NULL) {
		if (check->key == oldkey){
			printf("found\n");
			//decrease total entry by 1
			mutex_lock(&vulnentry_lock);
			vulnentries--;
			mutex_unlock(&vulnentry_lock);

			//decrease total count by val
			mutex_lock(&vulncount_lock);
			vulncount = vulncount - check->val;
			mutex_unlock(&vulncount_lock);

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
void vulnhash_increment(struct vulnhash *self, unsigned short check){
	//unsigned int hashkey = hash2(check) % self->TableSize;
	//printf("key is %d\n", self->buffer[hashkey].key);
	/*if (self->buffer[hashkey].key != 0){
		self->buffer[hashkey].val++;
		//printf("number is %d\n", self->buffer[hashkey].val);
	}*/

	unsigned int hashkey = hash2(check) % self->TableSize;
	struct couple* temp = self->buffer[hashkey].next;
	while(temp != NULL) {
		if (temp->key == check){
			temp->val++;

			//increase total count by 1
			mutex_lock(&vulncount_lock);
			vulncount++;
			mutex_unlock(&vulncount_lock);
		}
		temp = temp->next;
	} 
	return;
}

void vulnhash_print(struct vulnhash *self){
	//Print out the statistics
	struct couple* printtemp;
	unsigned int addr;
	printf("print statistics\n");
	printf("count      vuln_source\n");
	for (int k=0; k < self->TableSize; k++){
		printtemp = self->buffer[k].next;
	  	while(printtemp != NULL){
	  		addr = switch_endian(printtemp->key);
	      	printf("%3d        0x%04x      |\n", printtemp->val, addr);
	     	printtemp = printtemp->next;
	    }
	}
	printf("total vuln count:        %d\n", vulncount);
	printf("total vuln entries:      %d\n", vulnentries);
}




