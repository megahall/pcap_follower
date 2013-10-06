#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "branch_prediction.h"
#include "capture.h"
#include "ievent.h"

#define MAX_PCAP_FILES 128
#define PCAP_FILE_COUNT 10
#define PCAP_FILE_COUNT_LEN "1"
#define SLEEP_INTERVAL_USECS 100

struct path {
    char path[PATH_MAX];
};

static int stdout_binary = 0;
static int wd_fd_map[MAX_PCAP_FILES];
static unsigned int fd_index_map[MAX_PCAP_FILES];
static struct path fd_path_map[MAX_PCAP_FILES];

void pcap_touch(char* pcap_path) {
    // create with 0644 so unprivileged tcpdump or tshark can see it
    int fd = open(pcap_path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        warn("could not touch %s", pcap_path);
    }
    else {
        int rv = close(fd);
        if (rv) { warn("could not close %s after touch", pcap_path); }
        
        rv = chmod(pcap_path, 0644);
        if (rv) { warn("could not chmod %s", pcap_path); }
        
        fprintf(stderr, "touched %s\n", pcap_path);
    }
}

void pcap_files_watch(int ifd, char* pcap_prefix) {
    int wd    = 0;
    int fd    = 0;
    char pcap_path[PATH_MAX];
    
    for (int i = 0; i < PCAP_FILE_COUNT; ++i) {
        snprintf(pcap_path, sizeof(pcap_path), "%s%0" PCAP_FILE_COUNT_LEN "d", pcap_prefix, i);
        fprintf(stderr, "preparing to watch file %s\n", pcap_path);
        pcap_touch(pcap_path);
        
        wd = inotify_add_watch(ifd, pcap_path, IN_MODIFY | IN_CLOSE_WRITE);
        if (wd < 0) { err(1, "watching file %s failed", pcap_path); }
        else { fprintf(stderr, "watching file %s succeeded wd %d\n", pcap_path, wd); }
        
        if (wd > MAX_PCAP_FILES) { err(1, "pcap file wd overflow"); }
        
        fd = open(pcap_path, O_RDONLY);
        if (fd < 0) { err(1, "open pcap %s failed", pcap_path); }
        fprintf(stderr, "wd %d created fd %d for file %s\n", wd, fd, pcap_path);
        
        wd_fd_map[wd] = fd;
        strncpy(fd_path_map[fd].path, pcap_path, sizeof(fd_path_map[fd].path));
        fd_path_map[fd].path[sizeof(fd_path_map[fd].path) - 1] = 0;
    }
}

int pcap_tx(unsigned int packet_index, uint8_t* packet, int length) {
    int rv;
    
    if (packet_index % 100000 == 0) {
        fprintf(stderr, "transmitting packets\n");
    }
    
    if (likely(stdout_binary)) {
        rv = write(STDOUT_FILENO, packet, length);
        if (rv != length) { err(1, "pcap data stdout write failed"); }
        return rv;
    }
    else {
        /*
        fprintf(stderr, "transmit packet number %'u size %d\n", packet_index, length);
        fprintf(stderr, "transmit packet number %'u size %d: [ ", packet_index, length);
        for (int i = 0; i < length; ++i) {
            fprintf(stderr, "%02hhx ", packet[i]);
        }
        fprintf(stderr, "]\n");
        */
        return length;
    }
}

int pcap_rx_all(int ifd, int wd, int fd) {
    int packet_count   = 0;
    int current_offset = 0;
    int bytes          = 0;
    int rv             = 0;
    capture_file_header_t fheader;
    capture_packet_header_t pheader;
    uint8_t packet[CAPTURE_MAXLEN];
    
    memset(&fheader, 0, sizeof(fheader));
    
    current_offset = lseek(fd, 0, SEEK_CUR);
    if (current_offset == (off_t) -1) { err(1, "could not determine offset for fd %d", fd); }
    
    if (current_offset == 0) {
        // give tcpdump time to start the file.
        do {
            fprintf(stderr, "fd %d reading file header\n", fd);
            bytes = read(fd, &fheader, sizeof(fheader));
            usleep(SLEEP_INTERVAL_USECS);
        } while (bytes == 0);
        
        if (bytes != sizeof(fheader)) {
            err(1, "could not read file header for fd %d", fd);
        }
        
        fprintf(stderr, "magic:     0x%08x\n",      fheader.magic);
        fprintf(stderr, "major:     %02d\n",        fheader.version_major);
        fprintf(stderr, "minor:     %02d\n",        fheader.version_minor);
        fprintf(stderr, "thiszone:  %+04d\n",       fheader.thiszone);
        fprintf(stderr, "sigfigs:   %04d\n",        fheader.sigfigs);
        fprintf(stderr, "snaplen:   %05d 0x%08x\n", fheader.snaplen, fheader.snaplen);
        fprintf(stderr, "linktype:  %02d\n",        fheader.linktype);
        
        if (fheader.magic != CAPTURE_MAGIC) {
            err(1, "fd %d has corrupt file header", fd);
        }
    }
    
    while (1) {
        bytes = read(fd, &pheader, sizeof(pheader));
        if (bytes == 0) {
            // fprintf(stderr, "fd %d stream of packets complete\n", fd);
            break;
        }
        else if (bytes != sizeof(pheader)) {
            err(1, "fd %d has corrupt packet", fd);
        }
        
        //fprintf(stderr, "read packet fd %d sec %d usec %d wlength %u clength %u\n",
        //    fd, pheader.time.sec, pheader.time.usec, pheader.wlength, pheader.clength);
        
        if (pheader.wlength > CAPTURE_MAXLEN) {
            err(1, "fd %d has corrupt packet length %u", fd, pheader.wlength);
        }
        
        bytes = read(fd, &packet, pheader.wlength);
        if (bytes != pheader.wlength) {
            err(1, "fd %d length %d has corrupt packet payload", fd, bytes);
        }
        
        ++fd_index_map[fd];
        pcap_tx(fd_index_map[fd], packet, pheader.wlength);
        ++packet_count;
    }
    
    fprintf(stderr, "packet count %d\n", packet_count);
    if (packet_count == 0) {
        rv = inotify_add_watch(ifd, fd_path_map[fd].path, IN_CLOSE_WRITE | IN_MODIFY);
        if (rv < 0) { err(1, "could not add watch for fd %d path %s", fd, fd_path_map[fd].path); }
    }
    else {
        rv = inotify_add_watch(ifd, fd_path_map[fd].path, IN_CLOSE_WRITE);
        if (rv < 0) { err(1, "could not suppress watch for fd %d path %s", fd, fd_path_map[fd].path); }
    }
    
    return packet_count;
}

int pcap_fd_check(int fd) {
    int rv = 0;
    char pcap_path[PATH_MAX];
    char proc_path[PATH_MAX];
    
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    rv = readlink(proc_path, pcap_path, sizeof(pcap_path));
    if (rv < 0) { warn("readlink failed on %s", proc_path); return 1; }
    
    fprintf(stderr, "pcap fd %d path %s\n", fd, pcap_path);
    
    return 0;
}

int main(int argc, char* argv[]) {
    int      c              = 0;
    int      rv             = 0;
    int      ifd            = 0;
    int      wd             = 0;
    int      fd             = 0;
    int      was_zero       = 0;
    // int      name_length    = 0;
    uint32_t mask           = 0;
    char*    pcap_directory = NULL;
    char*    pcap_prefix    = NULL;
    struct stat pcap_stat;
    struct ievent event;
    
    memset(&wd_fd_map,    0, sizeof(wd_fd_map));
    memset(&fd_index_map, 0, sizeof(fd_index_map));
    memset(&pcap_stat,    0, sizeof(pcap_stat));
    memset(&event,        0, sizeof(event));
    
    while ( (c = getopt(argc, argv, ":bd:f:")) != -1 ) {
        switch (c) {
            case 'b': {
                stdout_binary = 1;
                break;
            }
            case 'd': {
                pcap_directory = optarg;
                break;
            }
            case 'f': {
                pcap_prefix = optarg;
                break;
            }
            case '?': default: {
                errx(1, "invalid option: %c", optopt);
                break;
            }
        }
    }
    
    if (pcap_directory == NULL) { errx(1, "pcap directory option -d is required"); }
    rv = stat(pcap_directory, &pcap_stat);
    if (rv) { err(1, "pcap directory invalid"); }
    rv = S_ISDIR(pcap_stat.st_mode);
    if (!rv) { err(1, "pcap directory is not a directory"); }

    if (pcap_prefix == NULL) { errx(1, "pcap file option -f is required"); }
    /*
    rv = stat(pcap_path, &pcap_stat);
    if (rv) { err(1, "pcap file invalid"); }
    rv = S_ISREG(pcap_stat.st_mode);
    if (!rv) { err(1, "pcap file is not a file"); }
    */
    
    ifd = inotify_init();
    if (ifd < 0) { err(1, "inotify_init failed"); }
    
    rv = chdir(pcap_directory);
    if (rv < 0) { err(1, "chdir failed on pcap directory"); }
    
    pcap_files_watch(ifd, pcap_prefix);
    
    while (1) {
        ssize_t bytes = read(ifd, &event, sizeof(event));
        if (bytes < sizeof(event.event)) { err(1, "incomplete inotify event"); }
        
        mask        = event.event.mask;
        wd          = event.event.wd;
        
        /*
        name_length = event.event.len;
        fprintf(stderr, "isize:   %zd\n", bytes);
        fprintf(stderr, "wd:      %d\n", wd);
        fprintf(stderr, "mask:    %u\n", mask);
        fprintf(stderr, "cookie:  %d\n", event.event.cookie);
        fprintf(stderr, "namelen: %d\n", name_length);
        if (name_length)
            fprintf(stderr, "name    %s\n", event.event.name);
        */
        
        fd = wd_fd_map[wd];
        if (fd < 0) { err(1, "corrupt wd_fd_map"); }
        
        /*
        rv = pcap_fd_check(fd);
        if (rv) { warn("pcap fd check failed"); }
        */
        
        rv = pcap_rx_all(ifd, wd, fd);
        if (rv <= 0 && !was_zero) {
            //fprintf(stderr, "wd %d fd %d read %d packets\n", wd, fd, rv);
            was_zero = 1;
        }
        else {
            was_zero = 0;
        }
        
        if (mask & IN_CLOSE_WRITE) {
            fprintf(stderr, "wd %d fd %d closed by tcpdump\n", wd, fd);
            
            fd_index_map[fd] = 0;
            rv = lseek(fd, SEEK_SET, 0);
            fprintf(stderr, "lseek rv %d\n", rv);
            if (rv) { err(1, "could not rewind fd %d", fd); }
            
            rv = inotify_add_watch(ifd, fd_path_map[fd].path, IN_CLOSE_WRITE | IN_MODIFY);
            if (rv < 0) { err(1, "could not add watch for fd %d path %s", fd, fd_path_map[fd].path); }
        }
        else if (mask & IN_MODIFY) {
            // fprintf(stderr, "wd %d fd %d modified\n", wd, fd);
        }
        else {
            err(1, "unknown mask %d", mask);
        }
    }
}
