#ifndef BASE64_H
#define BASE64_H
int Base64Encode(const char* message, char** buffer);
int Base64Decode(char* b64message, char** buffer);
#endif /* defined(BASE64_H) */

