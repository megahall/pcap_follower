#ifndef __IEVENT_H__
#define __IEVENT_H__

#include <limits.h>
#include <sys/inotify.h>

struct ievent {
    struct inotify_event event;
    char name[PATH_MAX * 2];
};

#endif // __IEVENT_H__
