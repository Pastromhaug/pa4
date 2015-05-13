#include "kernel.h"

int totalcount = 0;
int totalentries = 0;

int count_lock = 0;
int entry_lock = 0;

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

struct hashtable {
    struct pair* buffer;
	int TableSize;
	int numElements;
};

void hashtable_create(struct hashtable *self){
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
void hashtable_add(struct hashtable *self, unsigned int newkey) {
	//printf("TableSize is %d\n", self->TableSize);
	unsigned int hashkey = hash(newkey) % self->TableSize;
	//struct pair** temp = &(self->buffer + hashkey);
	//printf("temp is %p\n", temp);

	// insert is the node that is being added
	struct pair* insert;
	// temp is temporary node to keep track of next
	

	struct pair* check;

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
		mutex_lock(&entry_lock);
		totalentries++;
		mutex_unlock(&entry_lock);

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
//	temp = (struct pair*)malloc(sizeof(struct pair));
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
void hashtable_delete(struct hashtable *self, unsigned int oldkey){
	/*unsigned int hashkey = hash(oldkey) % self->TableSize;
	if(self->buffer[hashkey].key != 0)
	{
		self->buffer[hashkey].key = 0;
		self->buffer[hashkey].val = 0;
		self->numElements--;
		//printf("deleted\n");
	}*/

	unsigned int hashkey = hash(oldkey) % self->TableSize;
	struct pair* check = self->buffer[hashkey].next;
	struct pair *temp = (self->buffer+hashkey);
	//printf("trying to delete %08x\n", oldkey);


	while(check != NULL) {
		if (check->key == oldkey){
			printf("found\n");
			//decrease total entry by 1
			mutex_lock(&entry_lock);
			totalentries--;
			mutex_unlock(&entry_lock);

			//decrease total count by val
			mutex_lock(&count_lock);
			totalcount = totalcount - check->val;
			mutex_unlock(&count_lock);

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
void hashtable_increment(struct hashtable *self, unsigned int check){
	//unsigned int hashkey = hash(check) % self->TableSize;
	//printf("key is %d\n", self->buffer[hashkey].key);
	/*if (self->buffer[hashkey].key != 0){
		self->buffer[hashkey].val++;
		//printf("number is %d\n", self->buffer[hashkey].val);
	}*/

	unsigned int hashkey = hash(check) % self->TableSize;
	struct pair* temp = self->buffer[hashkey].next;
	while(temp != NULL) {
		if (temp->key == check){
			temp->val++;

			//increase total count by 1
			mutex_lock(&count_lock);
			totalcount++;
			mutex_unlock(&count_lock);
		}
		temp = temp->next;
	} 
	return;
}



