#include "kernel.h"
#include "machine.h"

#define RING_SIZE 16
#define BIG_RING_SIZE 100
#define BUFFER_SIZE 4096

// a pointer to the memory-mapped I/O region for the console
volatile struct dev_net *dev_net;
struct dma_ring_slot* Big_Ring;
unsigned int Big_head;
unsigned int Big_tail;
//unsigned int Big_handle_index;









//struct hashtable Spammer;
//struct hashtable Evil;
//struct hashtable Vulnerable;






// Initializes the network driver, allocating the space for the ring buffer.
void network_init(){
	/* Find out where the I/O region is in memory. */
  for (int i = 0; i < 16; i++) {
    if (bootparams->devtable[i].type == DEV_TYPE_NETWORK) {
      // find a virtual address that maps to this I/O region
      dev_net = physical_to_virtual(bootparams->devtable[i].start);
      puts("Detected network device...");
      // set cmd to turn on network
      dev_net->cmd = NET_SET_POWER;
      dev_net->data = 1;
      //Allocate memory for ring buffer
      struct dma_ring_slot* ring = (struct dma_ring_slot*) malloc(sizeof(struct dma_ring_slot) * RING_SIZE);
      //rx_base variable to physical address of start of array
      dev_net->rx_base = virtual_to_physical(ring);
      //rx_capacity set to number of ring slots
      dev_net->rx_capacity = RING_SIZE;
      dev_net->rx_head = 0;
      dev_net->rx_tail = 0;

      // initialize each ring slot and store address in dma_base
      // and length in dma_len
      for (int i = 0; i < RING_SIZE; i++){
      	void* space = malloc(BUFFER_SIZE);
      	ring[i].dma_base = virtual_to_physical(space);
      	ring[i].dma_len = BUFFER_SIZE;	
      }

      //initialize Big_Ring
      Big_Ring= (struct dma_ring_slot*) malloc(sizeof(struct dma_ring_slot) * BIG_RING_SIZE);
      for (int i = 0; i < BIG_RING_SIZE; i++){
              void* space = malloc(BUFFER_SIZE);
              Big_Ring[i].dma_base = virtual_to_physical(space);
              Big_Ring[i].dma_len = BUFFER_SIZE;  
      }
      Big_head=0;
      Big_tail=0;


      return;
    }
  }
}

void network_start_receive(){
	if (!dev_net){
		return;
	} 
	else {
	// set cmd to start receiving
	dev_net->cmd = NET_SET_RECEIVE;
	dev_net->data = 1;
	return;
	}
}

void network_set_interrupts(){
	if (!dev_net){
		return;
	} 
	else {
	dev_net->cmd = NET_SET_INTERRUPTS;
	dev_net->data = 1;
	return;
	}
}


void network_trap(){
	// when interrupt occurs, handle the packet
	// read statistics, etc etc
  printf("YAY");
	return;
}

void network_poll(){

  while (1){
    //ringtest is the pointer to the ring
    struct dma_ring_slot* small_ring = physical_to_virtual(dev_net->rx_base);

    if(dev_net->rx_tail != dev_net->rx_head){
       int index = dev_net->rx_tail % dev_net->rx_capacity;
       int Big_Index = Big_head % BIG_RING_SIZE;
      // ringptr is the pointer to the ring buffer
      void* ringptr= physical_to_virtual(small_ring[index].dma_base);
      //Place ringptr from small ring to big ring
      Big_Ring[Big_Index].dma_base =(unsigned int) ringptr;
      Big_Ring[Big_Index].dma_len = BUFFER_SIZE;
      //increment head of big ring
      Big_head++;

      //malloc space for a new buffer in small ring
      void* space = malloc(BUFFER_SIZE);
      small_ring[index].dma_base = virtual_to_physical(space);
      small_ring[index].dma_len = BUFFER_SIZE;

      //Increment tail of small ring
      dev_net->rx_tail++;
    }
  }

  void network_handle(){
    // next order of business is to figure out how to access the Big_Ring in a concurrency-safe method





    //analyze packets, execute commands

    // retrieve the packet from memory

    // look at the secret
    /*
    // look at the secret
    struct honeypot_command_packet *temp = queue_get(memq)->packet;
    unsigned short secret = temp->secret_big_endian;
    printf("secret is %d\n", secret);

    // if secret is 3410, treat as a cmd packet
    if (secret == 4148){
      // find the cmd packet
      unsigned short cmd = temp->cmd_big_endian;
      if (cmd == HONEYPOT_ADD_SPAMMER){
        // add address to list of spammer addresses
      }
      else if (cmd == HONEYPOT_ADD_EVIL){
        //add evil hash value to hashtable
      }
      else if(cmd == HONEYPOT_ADD_VULNERABLE){
        // add port to list of vulnerable ports
      }
      else if (cmd == HONEYPOT_DEL_SPAMMER){
        //remove address from list of spammer addresses
      }
      else if(cmd == HONEYPOT_DEL_EVIL){
        // remove hash value from evil hashtable
      }
      else if (cmd == HONEYPOT_DEL_VULNERABLE){
        // remove port from list of vulnerable ports
      }
      else if(cmd == HONEYPOT_PRINT){
        // Print out the statistics
    }
    // else treat like a non-cmd packet
    else{

      //look at source address and see if it is in list
      unsigned int saddr=temp->headers->ip_source_address_big_endian; 
      if (saddr is in list of spammer addresses){
        update accordingly
      }

      //look at destination port
      unsigned int dest=temp->headers->udp_dest_port_big_endian; 
      if (dest is in list of vulnerable ports){
        update accordingly
      }

      //check the hash and see if it is an evil packet
      hash = djb2(*(honeypot_command_packet *)temp);
      if (hash is in hashtable){
        update hashtable accordingly
      }
    }

    //update global stats
    // note that the global stats need to be concurrency safe, aka need to use
    // ll and sc
    update number of packets arrived and packets per second
    // note that bytes and bits per second should be updated by the poller

    printf("secret is %d\n", secret);
    */
    return;
  }
}


