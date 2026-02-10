// Minimal servidor.c: accept connections, parse NUL-separated args, handle
// RPC_BUILD -> print "s> SEND <num> <text>" and reply with a phrase.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define SERVER_PORT       8080
#define BACKLOG           10
#define MSG_BUFFER_SIZE   2048

volatile sig_atomic_t keep_running = 1;
int sfd_global = -1;

static int parse(char *buf, int buflen, char **args, int max_args) {
    int argc = 0;
    char *p = buf;
    while ((p < buf + buflen) && (argc < max_args)) {
        args[argc++] = p;
        while (*p != '\0' && (p < buf + buflen - 1)) p++;
        if (*p == '\0') p++; else break;
    }
    return argc;
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\nSIGINT received, shutting down server...\n");
        fflush(stdout);
        keep_running = 0;
        if (sfd_global != -1) {
            shutdown(sfd_global, SHUT_RDWR);
            close(sfd_global);
            sfd_global = -1;
        }
    }
}

void *handle_client(void *arg) {
    int fd = *(int *)arg;
    free(arg);

    char buf[MSG_BUFFER_SIZE];
    char *args[10];

    ssize_t bytes_received = recv(fd, buf, MSG_BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(fd);
        return NULL;
    }
    buf[bytes_received] = '\0';

    int argc = parse(buf, bytes_received, args, 10);
    if (argc >= 3 && strcmp(args[0], "RPC_BUILD") == 0) {
        int number = atoi(args[1]);
        char response[512];

        // Requested server log: "SEND NUMERO TEXTO"
        printf("s> SEND %s %s\n", args[1], args[2]);
        fflush(stdout);

    snprintf(response, sizeof(response), "El numero es %d y la frase %s", number, args[2]);
    send(fd, response, strlen(response) + 1, 0); // NUL-terminated

    // Also send the number as a separate NUL-terminated string
    char numbuf[64];
    snprintf(numbuf, sizeof(numbuf), "%d", number);
    send(fd, numbuf, strlen(numbuf) + 1, 0);
        close(fd);
        return NULL;
    }

    // Unknown command: just close connection
    close(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = SERVER_PORT;
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        if (opt == 'p') port = atoi(optarg);
        else { fprintf(stderr, "Usage: %s [-p port]\n", argv[0]); exit(EXIT_FAILURE); }
    }

    signal(SIGINT, signal_handler);

    sfd_global = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd_global < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int reuse = 1;
    if (setsockopt(sfd_global, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed"); close(sfd_global); exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sfd_global, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); close(sfd_global); exit(EXIT_FAILURE); }
    if (listen(sfd_global, BACKLOG) < 0) { perror("listen"); close(sfd_global); exit(EXIT_FAILURE); }

    printf("s> init server 0.0.0.0:%d (minimal)\n", port);
    fflush(stdout);

    while (keep_running) {
        int *cfd_ptr = malloc(sizeof(int));
        if (!cfd_ptr) { perror("malloc for client fd"); continue; }

        *cfd_ptr = accept(sfd_global, NULL, NULL);
        if (*cfd_ptr < 0) {
            free(cfd_ptr);
            if (errno == EINTR && !keep_running) break;
            if (keep_running && errno != EINTR) perror("accept");
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, cfd_ptr) != 0) {
            perror("pthread_create");
            free(cfd_ptr);
            close(*cfd_ptr);
        } else {
            pthread_detach(tid);
        }
    }

    if (sfd_global != -1) { close(sfd_global); sfd_global = -1; }
    printf("s> Servidor minimal apagado.\n");
    return 0;
}