#include "kernel.h"
#include "machine.h"
#include "spamhash.h"
#include "vulnhash.h"

#define RING_SIZE 16
#define BIG_RING_SIZE 100
#define BUFFER_SIZE 4096

// a pointer to the memory-mapped I/O region for the console
volatile struct dev_net *dev_net;
struct spamhash spam;
struct vulnhash vulports;

//mutex locks
int tail_lock = 0;
int malloc_lock = 0;
int free_lock = 0;
int print_lock = 0;
int pkts_lock = 0;
int bytes_lock = 0;

//struct hashtable Spammer;
//struct hashtable Evil;
//struct hashtable Vulnerable;

//Citation for switch endian function
//http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func
unsigned int switch_endian(unsigned int num){
  unsigned int swapped;
  swapped = ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
  return swapped;
}

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
      Big_head=0;
      Big_tail=0;


      //initialize the hashtables
      spamhash_create(&spam);
      vulnhash_create(&vulports);
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
      //let dma_len of big ring to be size of the packet in bytes
      Big_Ring[Big_Index].dma_len = (small_ring[index].dma_len);
      //increment head of big ring
      
      //printf("Big_head is %d\n", Big_head);
      //printf("Big_Index is %d\n", Big_Index);
      //struct honeypot_command_packet *test = (struct honeypot_command_packet*)Big_Ring[Big_Index].dma_base;
      //unsigned short secret = test->secret_big_endian;
      //printf("secret is %d\n", secret);
      Big_head++;
      //print secret for testing
      //unsigned short secret = ((struct honeypot_command_packet*)Big_Ring[Big_Index].dma_base)->secret_big_endian;
      //printf("secret is %d\n", secret);

      //malloc space for a new buffer in small ring
      mutex_lock(&malloc_lock);
      void* space = malloc(BUFFER_SIZE);
      mutex_unlock(&malloc_lock);

      small_ring[index].dma_base = virtual_to_physical(space);
      small_ring[index].dma_len = BUFFER_SIZE;

      //Increment tail of small ring
      dev_net->rx_tail++;
    }
  }
}

  void network_handle(){
    // next order of business is to figure out how to access the Big_Ring in a concurrency-safe method

    // use mutex lock to read from Big_Ring
    // free the space containing that packet
    unsigned short secret;
    while (1){
      
      mutex_lock(&tail_lock);
      if (Big_head != Big_tail){
        Big_handle_index = Big_tail % BIG_RING_SIZE;
        struct honeypot_command_packet *retrieve = (struct honeypot_command_packet*)Big_Ring[Big_handle_index].dma_base;

        //free that buffer
        mutex_lock(&free_lock);
        free((void*)Big_Ring[Big_handle_index].dma_base);
        mutex_unlock(&free_lock);

        //printf("2\n");
        //Increment Big_tail
        //printf("Big_tail is %d\n", Big_tail);
        //printf("Big_handle_index is %d\n", Big_handle_index);
        unsigned int num_bytes = Big_Ring[Big_handle_index].dma_len;
        Big_tail++;
        mutex_unlock(&tail_lock);



         //update global stats
        // total packet number increases by 1
        mutex_lock(&pkts_lock);
        total_pkts++;
        mutex_unlock(&pkts_lock);
        // total byte number increases by number of bytes
        mutex_lock(&bytes_lock);
        total_bytes = total_bytes + num_bytes;
        mutex_unlock(&bytes_lock);
        //printf("total packets is %d\n", total_pkts);
        //printf("total bytes is %d\n", total_bytes);


        secret = retrieve->secret_big_endian;
        //printf("secret is %d\n", secret);
        // if secret is 3410, treat as a cmd packet
        if (secret == 4148){
          // find the cmd packet
          unsigned short cmd = retrieve->cmd_big_endian;
         //printf("cmd is %d\n", cmd);
          if (cmd == 0x101){
            // add address to list of spammer addresses
            spamhash_add(&spam, retrieve->data_big_endian);
          }
          else if (cmd == 0x201){
            //add evil hash value to hashtable
           // printf("add evil\n");
          }
          else if(cmd == 0x301){
            // add port to list of vulnerable ports
            //printf("data is %d\n", retrieve->data_big_endian);
            vulnhash_add(&vulports, retrieve->data_big_endian);
          }
          else if (cmd == 0x102){
            //remove address from list of spammer addresses
            spamhash_delete(&spam, retrieve->data_big_endian);
          }
          else if(cmd == 0x202){
            // remove hash value from evil hashtable
            //printf("del evil\n");
          }
          else if (cmd == 0x302){
            // remove port from list of vulnerable ports
            vulnhash_delete(&vulports, retrieve->data_big_endian);
          }
          else if(cmd == 0x103){
            mutex_lock(&print_lock);
            spamhash_print(&spam);
            vulnhash_print(&vulports);
            mutex_unlock(&print_lock);
          }
        }
        // else treat like a non-cmd packet
        else{
          //look at source address and see if it is in list
          struct packet_header what = retrieve->headers;
          unsigned int saddr=what.ip_source_address_big_endian;
          //printf("saddr is %d\n", saddr); 
          spamhash_increment(&spam, saddr);

          //look at destination port
          unsigned int dest=what.udp_dest_port_big_endian;
          //printf("dest is %d\n", dest); 
          vulnhash_increment(&vulports, dest);

          //check the hash and see if it is an evil packet
          //hash = djb2(*(honeypot_command_packet *)temp);
          //if (hash is in hashtable){
           // update hashtable accordingly
          //}
        }
      }
      else mutex_unlock(&tail_lock);
    }
    // note that the global stats need to be concurrency safe, aka need to use
    // ll and sc
    //update number of packets arrived and packets per second
    // note that bytes and bits per second should be updated by the poller
    //return;
}



