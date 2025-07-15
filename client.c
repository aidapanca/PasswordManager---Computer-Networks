#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

extern int errno;
int port;

/* Update client-side command help */
static void show_usage() {
    printf("Available commands:\n");
    printf(" REGISTER|username|masterPass\n");
    printf(" REGISTER_SEC|username|masterPass|securityQ|securityA\n");
    printf(" LOGIN|username|masterPass\n");
    printf(" SEC_QUESTION|username\n");
    printf(" RECOVER_PASS|username|securityA   ---   this will change the password of the user to \"password\"\n");
    printf(" CHANGE_PASS|username|oldPass|newPass\n");
    printf(" NEW_CAT|categoryName\n");
    printf(" LIST_CATS\n");
    printf(" NEW_ENTRY|categoryName|title|user|url|notes|password\n");
    printf(" LIST_ENTRIES|categoryName\n");
    printf(" MOD_ENTRY|oldTitle|newTitle|newUser|newURL|newNotes|newPass\n");
    printf(" DEL_ENTRY|title\n");
    printf(" DEL_CAT|categoryName\n");
    printf(" LOGOUT\n");
    printf(" EXIT\n");
}

int main(int argc, char *argv[])
{
    int sd;
    struct sockaddr_in server;
    char buffer[4096];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return -1;
    }

    port = atoi(argv[2]);

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation error.\n");
        return errno;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(port);

    if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("Connect error.\n");
        return errno;
    }

    show_usage();

    while (1) {
        printf("PasswordManager> ");
        fflush(stdout);

        if (!fgets(buffer, sizeof(buffer), stdin)) {
            perror("Input error.\n");
            break;
        }

        // Remove trailing newline
        buffer[strcspn(buffer, "\n")] = '\0';

        // Send command to server
        if (write(sd, buffer, strlen(buffer)) <= 0) {
            perror("Write to server failed.\n");
            break;
        }

        if (strcmp(buffer, "EXIT") == 0) {
            printf("Exiting client...\n");
            break;
        }

        // Await server response
        int recv_len = read(sd, buffer, sizeof(buffer) - 1);
        if (recv_len < 0) {
            perror("Read from server failed.\n");
            break;
        }
        buffer[recv_len] = '\0';
        printf("Server: %s\n", buffer);
    }

    close(sd);
    return 0;
}
