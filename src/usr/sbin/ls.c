int main() {
    // opendir("."); // calls open(".", O_READONLY | O_DIRECTORY)
    // while(!readdir()) {} // calls readdir or getdents syscall in loop
    // // format and print names
    // closedir();  // close(fd)
}