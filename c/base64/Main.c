#include <stdio.h>

int main() {
  //Encode To Base64
  char* base64EncodeOutput;
  Base64Encode("Hello World", &base64EncodeOutput);
  printf("Output (base64): %s\n", base64EncodeOutput);

  //Decode From Base64
  char* base64DecodeOutput;
  Base64Decode("SGVsbG8gV29ybGQ=", &base64DecodeOutput);
  printf("Output: %s\n", base64DecodeOutput);
  
  return(0);
}