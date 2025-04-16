#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("test.txt", O_CREAT | O_WRONLY, 0644);
    write(fd, "Hello, World!\n", 14);
    close(fd);

    char buffer[100];
    fd = open("test.txt", O_RDONLY);
    read(fd, buffer, sizeof(buffer));
    close(fd);

    printf("Read from file: %s\n", buffer);

    return 0;
}
