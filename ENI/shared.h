#pragma once

#define SHARED_MAGIC 0x88EE88EE 

#define CMD_READ  1
#define CMD_WRITE 2
#define CMD_BASE  3

// Shutdown States
#define SHUTDOWN_NONE 0
#define SHUTDOWN_REQUESTED 1
#define SHUTDOWN_CONFIRMED 2

struct _COMM_BUFFER {
    volatile int lock;
    unsigned long long magic;
    int operation;

    unsigned long long target_pid;
    unsigned long long address;
    unsigned long long size;

    unsigned long long base_out;
    int status;

    // New Handshake variables
    volatile int shutdown_state;

    unsigned char data[4096];
};