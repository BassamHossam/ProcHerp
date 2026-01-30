#include "obfuscation.h"

unsigned long CalculateStringHashA(char* string) {
    unsigned long hashValue = 5381;
    int character;
    char* currentPointer = string;

    while ((character = *currentPointer++)) {
        hashValue = ((hashValue << 5) + hashValue) + character;
    }
    return hashValue;
}

unsigned long CalculateStringHashW(wchar_t* string) {
    unsigned long hashValue = 5381;
    int character;
    wchar_t* currentPointer = string;

    while ((character = *currentPointer++)) {
        // Convert lowercase to uppercase for case-insensitive hashing
        if (character >= 'A' && character <= 'Z') { 
            character += 32; 
        }
        hashValue = ((hashValue << 5) + hashValue) + character;
    }
    return hashValue;
}
