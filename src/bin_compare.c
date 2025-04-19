#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;

typedef struct {
    u8 *content;
    int size;
} FileContent;

FileContent read_file_into_memory(char *filename)
{
    FileContent result = {0};

    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        int size = ftell(file);
        fseek(file, 0, SEEK_SET);

        u8 *content = (u8 *)malloc(size);
        fread(content, size, 1, file);
        fclose(file);
    }

    return result;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "USAGE: %s <file1> <file2>.\n", argv[0]);
        exit(1);
    }

    char *filename1 = argv[1];
    char *filename2 = argv[2];

    FileContent file1_content = read_file_into_memory(filename1);
    FileContent file2_content = read_file_into_memory(filename2);

    if (file1_content.size != file2_content.size) {
        printf("Files are not equal. Different sizes\n");
        exit(2);
    }

    int result = memcmp(file1_content.content, file2_content.content, file1_content.size);
    if (result == 0) {
        printf("Files are equal :D!\n");
    } else {
        printf("Files are not equal :(");
    }

    return 0;
}
