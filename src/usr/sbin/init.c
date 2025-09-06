#include <libc/unistd.h>

uint64_t counter = 0;
int main() {
    for(;;) {
        counter++;

        if(counter % 500 == 0) {
            // yield();
        }

        if(counter > 1000) {
            exit(-1);
        }
    }
}