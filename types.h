#ifndef __TYPES__H
#define __TYPES__H

typedef unsigned char      byte;
typedef unsigned char      ubyte;
typedef unsigned char      uint8;
typedef unsigned short     uint16; 
typedef unsigned int       uint32;
typedef unsigned long long uint64;

typedef          char      sbyte;
typedef          char      sint8;
typedef          short     sint16; 
typedef          int       sint32;
typedef          long long sint64;

typedef float              real;
typedef float              real32;
typedef double             real64;

typedef unsigned int guint;
typedef uint32 guint32;
typedef uint16 guint16;
typedef uint8  guint8;

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif
#endif

