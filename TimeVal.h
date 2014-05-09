#ifndef __TIME_VAL_H__
#define __TIME_VAL_H__

#include <iostream>
#include <iomanip>
#include <sys/time.h>
#include <time.h>
#include "types.h"

typedef struct timeval TimeVal;

#define MSEC_IN_SEC 1000
#define USEC_IN_SEC 1000000
#define USEC_IN_MSEC 1000

inline bool operator<(struct timeval a, struct timeval b) {
    return (a.tv_sec < b.tv_sec) || ((a.tv_sec == b.tv_sec) && (a.tv_usec < b.tv_usec));
}

inline bool operator>(struct timeval a, struct timeval b) {
    return (a.tv_sec > b.tv_sec) || ((a.tv_sec == b.tv_sec) && (a.tv_usec > b.tv_usec));
}

inline bool operator==(struct timeval a, struct timeval b) {
    return (a.tv_sec == b.tv_sec) && (a.tv_usec == b.tv_usec);
}

inline bool operator<=(struct timeval a, struct timeval b) {
    return a < b || a == b;
}

inline bool operator>=(struct timeval a, struct timeval b) {
    return a > b || a == b;
}

inline bool operator!=(struct timeval a, struct timeval b) {
    return !(a == b);
}

inline struct timeval operator+(struct timeval a, double add_msec) {
    struct timeval ret;

    // convert into sec/usec parts
    sint32 sec_part  = (sint32)(add_msec/MSEC_IN_SEC);
    sint32 usec_part = (sint32)((add_msec - sec_part * MSEC_IN_SEC)*USEC_IN_MSEC);

    // do the initial addition
    ret.tv_sec  = a.tv_sec + sec_part;
    ret.tv_usec = a.tv_usec + usec_part;

    // perform a carry if necessary
    if (ret.tv_usec > USEC_IN_SEC) {
	ret.tv_sec++;
	ret.tv_usec = ret.tv_usec % USEC_IN_SEC;
    } else if (ret.tv_usec < 0) {
	ret.tv_sec--;
	ret.tv_usec = USEC_IN_SEC + ret.tv_usec;
    }

    return ret;
}

inline int64_t operator-(struct timeval a, struct timeval b) {
    return ((sint64)a.tv_sec - (sint64)b.tv_sec)*USEC_IN_SEC + 
	((sint64)a.tv_usec - (sint64)b.tv_usec);
}

inline float timeval_to_float (struct timeval a)
{
    return (float) a.tv_sec + ((float) a.tv_usec / USEC_IN_SEC);
}

inline std::ostream& operator<<(std::ostream& os, const TimeVal& t) 
{
    return os << &t;
}

#ifndef HAVE_TIMEVAL_OUT
#define HAVE_TIMEVAL_OUT
inline std::ostream& operator<<(std::ostream& os, const TimeVal* t)
{
    return os << t->tv_sec << "." << std::setw(6) << std::setfill('0') << t->tv_usec;
    
}
#endif

extern TimeVal TIME_NONE;

#endif
