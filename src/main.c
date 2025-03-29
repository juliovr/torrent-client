#include <stdio.h>

int main(int argc, char **argv)
{
    char *filename = "test_data/kubuntu-24.04.2-desktop-amd64.iso.torrent";
    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        int size = ftell(file);
        fseek(file, 0, SEEK_SET);

        printf("file size = %d\n", size);

        const int buffer_size = 255;
        char buffer[buffer_size];
        while (fgets(buffer, buffer_size, file)) {
            printf("%s", buffer);
        }

        fclose(file);
    }
    
    return 0;
}
