/* STRUCTS */
struct msgbuf {
    long mtype;         /* message type, must be > 0 */
    char mtext[0x10];   /* message data of size 16 */
};
struct arg_struct {
    long mtype;                 /* message type, must be > 0 */
    void * filter_function;     /* function to pull out specific nibbles from a variable */
    void * process_function;    /* function that "processes" nibbles from filter_function */
};


/* GLOBALS */
int deliver_msg_queue;
int receive_msg_queue;


/* THREAD_RUN */
void thread_run(arg_struct *arg) {
    long stack_canary;
    int rand1;
    int rand2;
    ssize_t sVar2;
    ulong flag_segment;
    ulong output;
    long in_FS_OFFSET;
    msgbuf message;

    stack_canary = *(long *)(in_FS_OFFSET + 0x28);

    // process 10-byte chunks until message queue dies
    do {
        // get message from deliver_msg_queue
        sVar2 = msgrcv(deliver_msg_queue, &message, 0x10, &arg->mtype, 0);

        // use the filter_function on the 10-byte chunk to pull out 5 nibbles
        flag_segment = (*(code *)arg->filter_function)(message.mtext);

        // process the 5 nibbles from the filter_function
        output = (*(code *)arg->process_function)(flag_segment);

        // flip 0-2 random bits of the output
        rand1 = rand();
        rand2 = rand();
        message.mtext._0_8_ = (1 << (rand2 & 0x3f)) ^ (1 << (rand1 & 0x3f)) ^ output;
            /* 
                Note that the output will be a 5-byte integer, and the "bit" that is flipped 
                can be any bit in a 8-byte integer, so it's possible that the "flipped" bit is
                not relevant (since only 5 bytes are written to output file).

                In addition, it's possible the same bit is flipped twice. 

                Therefore, 0-2 random bits are flipped.
            */
        
        // send the response to receive_msg_queue
        message.mtype = &arg->mtype;
        rand1 = msgsnd(receive_msg_queue, &message, 0x10, 0);
    } while (sVar2 >= 0);

    if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
    }
    __stack_chk_fail();
}