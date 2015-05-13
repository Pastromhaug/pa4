#ifndef NETWORK_H_
#define NETWORK_H_

#include "machine.h"
#include "honeypot.h"

extern int tail_lock;
extern int malloc_lock;
extern int free_lock;
extern int pkts_lock;
extern int bytes_lock;

extern struct spamhash spam;
extern struct vulnhash vulports;
extern struct evilhash evil;

unsigned int switch_endian(unsigned int num);

unsigned long djb2(unsigned char *pkt, int n);

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
