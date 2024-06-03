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


/* FUNCTION DEFINITIONS */
uint filter1(char* param);
uint filter2(char* param);
uint filter3(char* param);
uint filter4(char* param);

uint process1(uint param);
uint process2(uint param);
uint process3(uint param);
uint process4(uint param);

void thread_run(arg_struct *arg);


/* GLOBALS */
int deliver_msg_queue;
int receive_msg_queue;
pthread_t *thread_array[4];     /* array to store created threads in main() */
arg_struct arg_array[4] = {     /* array to store arguments for thread_run() */
    {1, &filter1, &process1},
    {2, &filter2, &process2},
    {3, &filter3, &process3},
    {4, &filter4, &process4}
};


/* MAIN */
int main(int argc, char **argv) {
    char pad_len;
    int inp;
    int output;
    int out;
    ssize_t sVar3;
    long in_FS_OFFSET;
    int i;
    int j;
    int x;
    int y;
    ulong contents_pos;
    size_t results_len;
    ulong nread;
    msgbuf flag_chunk;
    char contents [0x500];
    char results [2568];
    long stack_canary;

    stack_canary = *(long *)(in_FS_OFFSET + 0x28);

    // ensure that the program is called with 2 arguments: ./messages input_file output_file
    if (argc < 3) {
        exit(-1);
    }

    // read input file
    inp = open(argv[1], 0 /* O_RDONLY */);
    if (inp < 0) {
        exit(-1);
    }

    // create output file with 0644 permissions
    output = open(argv[2], 0x42 /* O_CREAT | O_RDWR */, 0644);
    if (output < 0) {
        exit(-1);
    }

    // create a message queue with W/R permissions to send messages to the threads
    deliver_msg_queue = msgget(0,01666);
    if (deliver_msg_queue < 0) {
        exit(-1);
    }

    // create a message queue with W/R permissions to receive messages from the threads
    receive_msg_queue = msgget(0,01666);
    if (receive_msg_queue < 0) {
        exit(-1);
    }

    // create 4 threads that will run thread_run() with different arguments
    for (i = 0; i < 4; i++) {
        pthread_create(thread_array[i], NULL, thread_run, arg_array[i]);
    }


    do {
        // read 1280 bytes from input_file
        nread = read(inp, contents, 0x500);
        
        // if len(contents) is not a multiple of 10, pad until it is
        if (nread % 10 != 0) {
            pad_len = 10 - (nread + ((nread / 10 << 2) + (nread / 10)) * -2);
            for (j = 0; j < pad_len; j++) {
                contents[j+nread] = pad_len;
            }
            nread += pad_len;
        }

        // loop through the contents 10 bytes at a time
        results_len = 0;
        for (contents_pos = 0; contents_pos < nread; contents_pos += 10) {

            // send the chunk to each of the threads
            for (x = 1; x < 5; x++) {
                flag_chunk.mtype = x;
                flag_chunk.mtext._8_8_ = *(ulong *)(contents[contents_pos+8]);
                flag_chunk.mtext._0_8_ = *(ulong *)(contents[contents_pos]);

                out = msgsnd(deliver_msg_queue, &flag_chunk, 0x10, 0);
                if (out != 0) {
                    perror("msgsnd-m");
                }
            }

            // receive the processed chunk from each of the threads and store in results buffer
            for (y = 1; y < 5; y++) {
                sVar3 = msgrcv(receive_msg_queue, &flag_chunk, 0x10, y, 0);
                if (sVar3 < 0) {
                    perror("msgrcv-m");
                }
                
                // copy the 5-byte message text to the results array
                memcpy(results[(y-1)*5 + results_len], flag_chunk.mtext, 5);
            }
            results_len += 0x14;
        }

        // write the "processed" data to the output file
        write(output, results, results_len);
    } while (0x4ff < nread); // keep reading bytes from the input file until we reach the end


    // cleanup
    out = msgctl(deliver_msg_queue, 0 /* IPC_RMID */, NULL);
    if (out == -1) {
        exit(1);
    }

    out = msgctl(receive_msg_queue, 0 /* IPC_RMID */, NULL);
    if (out == -1) {
        exit(1);
    }

    close(inp);
    close(output);

    if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
    }
    __stack_chk_fail();
}