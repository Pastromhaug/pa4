void mutex_lock(int *m) {
	asm volatile(".set mips2");
	asm volatile("test_and_set: ADDIU $8, $0, 1");
	asm volatile(	"LL $9, 0($4)");
	asm volatile(	"BNEZ $9, test_and_set");
	asm volatile(	"SC $8, 0($4)");
	asm volatile(	"BEQZ $8, test_and_set");
	return;
   
}

void mutex_unlock(int *m) {
	asm volatile("SW $0, 0($4)");
	return;
}

//citation for mutex lock code
//Lecture slides, Hakim Weatherspoon CS 3410 Cornell University