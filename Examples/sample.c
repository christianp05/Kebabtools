#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

__declspec (dllexport) int stuff(){
        printf("Break here please\n");
}
int main(){

        char* yeet = malloc(32);
        printf("Alloced at: 0x%llx",yeet-16);
        stuff();
} 