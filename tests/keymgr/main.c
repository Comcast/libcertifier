#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#define FIFO_PATH_MAX_LENGTH 128
#define PASSWORD_IN "changeit"
#define PASSWORD_IN_LENGTH 8
#define PASSWORD_OUT "newpass"
#define PASSWORD_OUT_LENGTH 7

static int manage_fifo(const char* fifo, const size_t fifo_len, const char* password, const size_t password_len)
{
    int rc = 0;

//    rc = mkfifo(fifo, 0666);
//    if (rc != 0 && errno != EEXIST)
//    {
//        perror("mkfifo");
//        return rc;
//    }

    int fd = open(fifo, O_WRONLY);
    if (fd < 0)
    {
        return 1;
    }

    write(fd, password, password_len);

    close(fd);

    return rc;
}

int main(int argc, char** argv)
{
    int rc = 0;
    int opt;
    char fifo_in[FIFO_PATH_MAX_LENGTH]  = "/tmp/certifier-fifo-in";
    char fifo_out[FIFO_PATH_MAX_LENGTH] = "/tmp/certifier-fifo-out";

    while ((opt = getopt(argc, argv, "io")) != - 1 && rc == 0) {
        switch (opt)
        {
            case 'i':
                rc = manage_fifo(fifo_in, sizeof(fifo_in), PASSWORD_IN, PASSWORD_IN_LENGTH);
                break;
            case 'o':
                rc = manage_fifo(fifo_out, sizeof(fifo_out), PASSWORD_OUT, PASSWORD_OUT_LENGTH);
                break;
            default:
                rc = 1;
        }
    }

    return rc;
}
