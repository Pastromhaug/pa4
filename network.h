#ifndef NETWORK_H_
#define NETWORK_H_

#include "machine.h"
#include "honeypot.h"

extern int tail_lock;
extern int malloc_lock;
extern int free_lock;
// Initializes the network driver, allocating the space for the ring buffer.
void network_init();

// Starts receiving packets!
void network_start_receive();

// If opt != 0, enables interrupts when a new packet arrives.
// If opt == 0, disables interrupts.
void network_set_interrupts();

// Continually polls for data on the ring buffer. Loops forever!
void network_poll();

// Called when a network interrupt occurs.
void network_trap();

//Fetch packet from memory and analyze
void network_handle();

void network_print();

#endif
