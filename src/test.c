#include<stdio.h>
#include<string.h>

void function(char **param1, char **param2) {
  *param1 = "Hello";
  *param2 = "World";
}

int main() {
   char *param1 = NULL;
   char *param2 = NULL;

   function(&param1, &param2);

   printf("Param1 is %s\n", param1);
   printf("Param2 is %s\n", param2);

   return 0;
}
