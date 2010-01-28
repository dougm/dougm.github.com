## HSCW Episode #38 - `sigar_arp_list_get()`

The `sigar_arp_list_get()` function returns the system ARP cache as an array of type `sigar_arp_t`, which includes:

* ifname - Network interface name

* type - Hardware type

* hwaddr - Hardware (link-layer) address

* address - IP address

* flags - State of the ARP cache entry

### Preamble

If you're not already familar with SIGAR, you are encouraged to read the [user documentation](http://sigar.hyperic.com/).  The primary functional goal of SIGAR is to provide a cross-platform API to gather system information from multiple languages.  One of the main design points is to implemention the functionality in-process, without having to execute external commands and parse their output.  This requires understanding what system commands are doing underneath so SIGAR can tap directly into the same data sources.

This document contain notes on the platform specific implementations of the `sigar_arp_list_get()` API. The notes are specific to the data gathered by the SIGAR API and as such do not cover the complete functionality of the given system command(s) we are emulating.  The information that follows has been captured for future reference by SIGAR developers and general interest for systems programmers.  It is terse in spots as much of what's written here are in note-to-self style.  We welcome any corrections and additions.  The resulting sources can be found on [github](http://github.com/hyperic/sigar/tree/master/src/os/).

### AIX

Let's start by using `truss` to trace the system calls made when invoking the `arp -an` command:

    % truss -f arp -an

The first point of interest in the truss output:

    340204: knlist(0x0000000110000B08, 5, 24) = 0 

`knlist()` is used to lookup the address of symbols exported by the kernel.  The addresses in turn are used as seek offsets when reading from a kernel device such as */dev/kmem*.  The first argument to *knlist()* is a pointer to an array of _struct nlist *_.  The second argument is the number of elements in the array and the third is the total sizeof the array.  The array is `NULL` terminated, so the `arp` command is really looking up *4* addresses.  Now on to the next *4* lines of the truss output:

    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF7F8, 0x0FFFFFFFFFFFF7F0, 4428264) = 8 
    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF800, 0x0FFFFFFFFFFFF7F0, 4428272) = 8 
    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF808, 0x0FFFFFFFFFFFF7F0, 7871696) = 8 
    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF810, 0x0FFFFFFFFFFFF7F0, 7871288) = 8 

First, what does `getkerninfo()` do?  Failing to find documentation at ibm.com, we grep */usr/include* and find in *net/proto_uipc.h*:

    int getkerninfo PROTO((int, char *, int *, int32long64_t)); 

Not too helpful.  We can infer *what* the function does given its name, still need to figure *how* it is used.  Looking at the grep output:

    /usr/include/sys/ndd.h: * Structure returned by getkerninfo KINFO_NDD

Hmm, several `KINFO_` defines in *sys/kinfo.h*, including:

    #define KINFO_READ (8<<8)

And with that, we have our first argument to `getkerninfo()` as `8<<8 == 2048`.  Smells like a wrapper or replacement of `seek()` and `read()`.  Making it safe to assume the second argument is a pointer to an output buffer and the third argument is the size of the buffer.  The fourth argument is would be an address in kernel space, those returned by `knlist()`.  Next question, what are the symbol names used by `arp` to lookup these addresses?  Easy to narrow down using the `strings` command:

    % strings /usr/sbin/arp | perl -ne 'print if /^arp\w+$/'
    arptabp
    arptabnb
    arptabsize
    arptab_bsiz

Whadda know, *4* names match.  Let's assume these are the symbols that the `arp` command is looking up, we need to know the data structure to get further.  Thanks again to grep, we see:

    /usr/include/net/if_arp.h:extern struct arptab  *arptabp;
    /usr/include/net/if_arp.h:extern long           arptabnb;
    /usr/include/net/if_arp.h:extern long           arptabsize;
    /usr/include/net/if_arp.h:extern long           arptab_bsiz;

Looks like `struct arptab` has exactly what we're looking for:

    /* 
     * Internet to link layer address resolution table. 
     */ 
    struct arptab {
        struct in_addr at_iaddr;   /* internet address */
        u_char hwaddr[MAX_HWADDR]; /* hardware address */ 
        ...

Now let's try to reproduce the initial calls to `getkerninfo()` with the following C program:

    int main(int argc, char `argv) {
       long arptabsize;
       long arptabnb;
       long arptabbsiz;
       struct arptab *arptabp;
     
       struct nlist klist[] = {
           {"arptabsize", 0, 0, 0, 0, 0}, 
           {"arptabnb", 0, 0, 0, 0, 0}, 
           {"arptab_bsiz", 0, 0, 0, 0, 0},
           {"arptabp", 0, 0, 0, 0, 0},
           {NULL, 0, 0, 0, 0, 0} 
       }; 
    
       if (knlist(klist, 
                  sizeof(klist) / sizeof(klist[0]), 
                  sizeof(klist[0])) != 0) 
       { 
           return errno; 
       } 
 
       size = sizeof(arptabsize); 
       getkerninfo(KINFO_READ, &arptabsize, &size, klist[0].n_value); 
 
       size = sizeof(arptabnb); 
       getkerninfo(KINFO_READ, &arptabnb, &size, klist[1].n_value); 
 
       size = sizeof(arptabbsiz); 
       getkerninfo(KINFO_READ, &arptabbsiz, &size, klist[2].n_value); 
 
       size = sizeof(arptabp); 
       getkerninfo(KINFO_READ, &arptabp, &size, klist[3].n_value); 
    }

Compile and trace:

    % xlc_r -w -q64 -o tarp tarp.c && truss ./tarp
    ...
    knlist(0x0FFFFFFFFFFFF9B8, 5, 24) = 0
    getkerninfo(2048, 0x0FFFFFFFFFFFF990, 0x0FFFFFFFFFFFF9B0, 4428264) = 8
    getkerninfo(2048, 0x0FFFFFFFFFFFF998, 0x0FFFFFFFFFFFF9B0, 4428272) = 8
    getkerninfo(2048, 0x0FFFFFFFFFFFF9A0, 0x0FFFFFFFFFFFF9B0, 7871696) = 8
    getkerninfo(2048, 0x0FFFFFFFFFFFF9A8, 0x0FFFFFFFFFFFF9B0, 7871288) = 8

Sure enough, the fourth argument to the `getkerninfo()` calls is filled in with the same values seen in the `truss arp -an` output.  Based on these results and looking closer at *net/if_arp.h*. Here's what we have so far:

* `struct arptabp *` - address of a hash table used to store the arp cache in kernel memory.

* `long arptabsize` - total size of the hash table.

* `long arptabnb` - number of buckets in the hash table.

* `long arptab_bsize` - bucket size - number of entries in each bucket.

Back to the `truss arp -an` output, there are a number of `getkerninfo()` calls that follow, *511* of which have the same pattern:

    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF818, 0x0FFFFFFFFFFFF7F0, -1080862866890817536) = 104 
    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF818, 0x0FFFFFFFFFFFF7F0, -1080862866890817432) = 104 
    340204: getkerninfo(2048, 0x0FFFFFFFFFFFF818, 0x0FFFFFFFFFFFF7F0, -1080862866890817328) = 104 
    ...

Where:

* The first argument is `KINFO_READ`

* The second argument is the same address each time (reusing a buffer).

* The third argument is the same address each time (reusing a size variable).

* The fourth (output) argument is an address incremented by *104* each time

* The return value is *104* - same value as the `sizeof(struct arptab)`

Going back to the *tarp.c* test program, changed to output the size variables:

* arptabsize == 511

* arptabnb == 73

* arptabbsiz == 7

So, the number of syscalls that return *104* == arptabsize == 511 == (73 * 7)

Clearly the `arp` command is iterating over the entire arp cache table, reading each entry from kernel memory, along the lines of:

    for (i=0; i<arptabsize; i++) { 
        struct arptab entry; 
        int size = sizeof(entry);
        getkerninfo(KINFO_READ, &entry, &size, arptabp + i);
    }

Now that we're able to read the entire table, let's focus on get the specific pieces of data we need.  The definition of `struct arptab` includes the flags, IP address and hardware address, but what about the hardware type and associated network interface name?  The system I'm testing on currently has 4 entries in the arp cache and truss shows the following when each entry is printed:

    340204: getkerninfo(2048, 0x0000000110001560, 0x0FFFFFFFFFFFF770, -1080862935453995008) = 408
    ...
    340204: kwrite(1, "     ?   ( 1 0 . 1 7 . 1".., 70)     = 70 

Another call to `getkerninfo()`, this time with a different return length, followed by the entry being printed on the console (kwrite).  What is being read here?

Looking again at the structure:

    struct arptab {
        ...
        struct ifnet *at_ifp; /* ifnet associated with entry */
        ...
    }

A pointer to:

    struct ifnet { 
        char *if_name; /* name, e.g. ``en'' or ``lo'' */ 
        ...
        u_char if_type; /* ethernet, tokenring, etc */ 
        ...
        u_char if_index; /* numeric abbreviation for this if  */ 
        ...
    }

Bingo: `sizeof(struct ifnet) == 408`.  *if_type* is the hardware type, the value of which would be one of the `IFT_` defines in *net/if_types.h*.  Since *if_name* is a pointer, we'll just use *if_index* to lookup the interface name using the `if_indextoname()` function.  Adding to the for loop of the test program, just need to check for a valid entry and the `struct ifnet` can be read using the address pointed to by *at_ifp*:

        if (entry.at_flags != 0) {
            struct ifnet ifb;
            size = sizeof(ifb);
            getkerninfo(KINFO_READ, &ifb, &size, entry.at_ifp);
        }

#### Notes

 * You'll want to check that the return value of `getkerninfo()` == expected_size

 * 64-bit kernel AIX requires a 64-bit calling process.

 * The user running the process must have privs to call `getkerninfo()`, e.g. *root*.

### Darwin

See: FreeBSD

### FreeBSD

Going into FreeBSD expecting to be using `sysctl()` to access the kernel data:

    % ktrace arp -an
    % kdump | grep -n3 sysctl
    ...
    298: 40900 arp      CALL  __sysctl(0x7fffffffe740,0x6,0,0x7fffffffe758,0,0)
    299: 40900 arp      RET   __sysctl 0
    300: 40900 arp      CALL  __sysctl(0x7fffffffe740,0x6,0x800902800,0x7fffffffe758,0,0)
    301: 40900 arp      RET   __sysctl 0
    302- 40900 arp      CALL  write(0x1,0x80090a000,0x36)
    303- 40900 arp      GIO   fd 1 wrote 54 bytes
    304-       "? (10.16.16.1) at 00:1b:90:ab:b1:41 on em0 [ethernet]
    ...

There's two calls to `sysctl()` just before printing out the arp cache table, both with the same `int *` array pointer and length of *6*.  In the first call the output buffer (3rd argument) is `NULL`, in which case `sysctl()` will set the size required to hold the data in the 4th `size_t*` argument.  The size is used to allocate the output buffer which is used in the 2nd call.  But hey, FreeBSD is open source, so let's take a peek at *usr.sbin/arp/arp.c*.  The `search` function has the key bits we need. The MIB names:

    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };

And how to dereference the generic `struct rt_msghdr *` which would be returned for any `sysctl` with a root of `CTL_NET` + `PF_ROUTE`, for our particular request of `RTF_LLINFO`:

    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        rtm = (struct rt_msghdr *)next;
        /* the IP address */
        sin = (struct sockaddr_inarp *)(rtm + 1);
        /* LLADDR(dsl) == hwaddr */
        /* sdl->sdl_index lookup w/ if_indextoname == ifname */
        sdl = (struct sockaddr_dl *)((char *)sin + SA_SIZE(sin));
        ...
    }

In turns out that the resulting implementation works as-is on *Darwin*, *NetBSD* and *OpenBSD*.  Four birds with one stone.  Hurrah!

### HP-UX

HP-UX provides an implementation of the standard `IP-MIB` via the */dev/ip* driver, wrapped by the `open_mib()` and `get_mib_info()` functions defined in *sys/mib.h*.  SIGAR uses this interface to implement `sigar_net_route_list_get()`, `sigar_net_connection_walk()` and other related functions.  Looking at `IP-MIB`:

    ipNetToPhysicalTable OBJECT-TYPE
        SYNTAX     SEQUENCE OF IpNetToPhysicalEntry
        MAX-ACCESS not-accessible
        STATUS     current
        DESCRIPTION "The IP Address Translation table used for mapping from IP addresses to physical addresses..."
     ...

    ipNetToMediaTable OBJECT-TYPE
        SYNTAX     SEQUENCE OF IpNetToMediaEntry
        MAX-ACCESS not-accessible
        STATUS     deprecated
        DESCRIPTION "The IPv4 Address Translation table used for mapping from IPv4 addresses to physical addresses.
                     This table has been deprecated, as a new IP version-neutral table has been added.
                     It is loosely replaced by the ipNetToPhysicalTable."

Alrighty then, let's check HP-UX 11.11 and 11.23, results are the same:

    % egrep 'ipNet.*Table' /usr/include/sys/mib.h
    #define ID_ipNetToMediaTableNum           OBJID(GP_ip,1031)
    #define ID_ipNetToMediaTable              OBJID(GP_ip,1032)
    #define ID_ipNetToMediaTableEnt           OBJID(GP_ip,1033)

Seems the deprecated `ipNetToMediaTable` is the only option.  Now to see what an entry in the table looks like:

    typedef struct {
        int             IfIndex;
        mib_physaddr_t  PhysAddr;
        ip_addr         NetAddr;
        int             Type;
    } mib_ipNetToMediaEnt;

That's just about everything we need.  First, let's see what HPUX's `arp` command is doing:

    % tusc /usr/sbin/arp -an
    ...
    open("/dev/dlpi", O_RDWR, 0) ........................................................... = 5
    putmsg(5, 0x7a000de8, NULL, NULL) ...................................................... = 0
    getmsg(5, 0x7a000de8, NULL, 0x7a000f98) ................................................ = 0
    ...
    write(1, "  ( 1 0 . 1 7 . 1 4 3 . 2 5 3 ) ".., 43) ..................................... = 43
    ...

Ah yes, the good old Data Link Provider Interface.  A bit more primitive than the mib wrappers, but likely the same information:

    % strings /usr/sbin/arp | grep ID_ipNetToMediaTable
    Can't get ID_ipNetToMediaTableNum
    Can't get ID_ipNetToMediaTable

Yep.  Sticking with */dev/ip*, here's gist of getting the table data:

    int fd, len, count, i, status;
    struct nmparms parms;
    mib_ipNetToMediaEnt *entries;

    if ((fd = open_mib("/dev/ip", O_RDONLY, 0, 0)) < 0) {
        return errno;
    }

    /* get the size of the table */
    len = sizeof(count);
    parms.objid = ID_ipNetToMediaTableNum;
    parms.buffer = &count;
    parms.len = &len;

    if ((status = get_mib_info(fd, parms)) != 0) {
        return status;
    }

    /* allocate buffer */
    len = count * sizeof(*entries);
    entries = malloc(len);

    /* get the table */
    parms.objid = ID_ipNetToMediaTable;
    parms.buffer = entries;
    parms.len = &len;

    if ((status = get_mib_info(fd, &parms)) != 0) {
        free(entries);
        return status;
    }
    /* iterate over the table */
    for (i=0; i<count; i++) {
        mib_ipNetToMediaEnt *entry = &entries[i];
        /* do what you will with entry */
    }

    free(entries);
    close_mib(fd);

### Linux

It's almost always the case with Linux that we'll be parsing files from the */proc* file system:

    % strace /sbin/arp -an 2>&1 | grep /proc
    open("/proc/net/arp", O_RDONLY) = 4

Sure enough:

    % cat /proc/net/arp 
    IP address       HW type     Flags       HW address            Mask     Device
    10.17.143.3      0x1         0x2         00:10:83:7B:50:91     *        eth0
    10.17.143.253    0x1         0x2         00:10:DB:EB:E0:83     *        eth0

Hey, easy to parse, right?  Sure, but this is also an example of inconsistency within Linux */proc*.  The *IP address* and *HW address* are already in human readable form.  Yet, in other */proc* files, addresses are in hex format.  Pfft.

### Solaris

Similar to HPUX, Solaris implements `MIB-II`, including `IP-MIB`, defined in the *inet/mib2.h* header file.  The query interface is quite different but the data structures are quite similar.  It appears only the deprecated version is implemented:

% egrep 'ipNet.*Table' /usr/include/inet/mib2.h 
 *      ipNetToMediaTable OBJECT-TYPE

And *ipNetToMediaEntry* is defined in *inet/mib2.h* as:

    typedef struct mib2_ipNetToMediaEntry { 
        /* Unique interface index               { ipNetToMediaEntry 1 } RW */ 
        DeviceName      ipNetToMediaIfIndex; 
        /* Media dependent physical addr        { ipNetToMediaEntry 2 } RW */ 
        PhysAddress     ipNetToMediaPhysAddress; 
        /* ip addr for this physical addr       { ipNetToMediaEntry 3 } RW */ 
        IpAddress       ipNetToMediaNetAddress; 
        /* other(1), inval(2), dyn(3), stat(4)  { ipNetToMediaEntry 4 } RW */ 
        int             ipNetToMediaType; 
        struct ipNetToMediaInfo_s { 
            PhysAddress     ntm_mask;       /* subnet mask for entry */ 
            int             ntm_flags;      /* ACE_F_* flags in arp.h */ 
        } ipNetToMediaInfo; 
    } mib2_ipNetToMediaEntry_t; 

That's the ticket.  Skimming through the output of `truss -f /usr/sbin/arp -an`:

    27460:  open("/dev/arp", O_RDWR)  = 3
    27460:  ioctl(3, I_PUSH, "tcp")   = 0
    27460:  ioctl(3, I_PUSH, "udp")   = 0
    27460:  ioctl(3, I_PUSH, "icmp")  = 0

That tell us the Solaris `arp` command is using the ARP stream device to retrieve IP MIB-II information.  Sun doesn't seem to provide any documentation on using the ARP device.  However, Vic Abell (of lsof fame), created a wrapper called *get_mib2*, which makes it simple to access the Solaris `MIB-II` data.  We've been using this wrapper in SIGAR for several years now.  The wrapper reads the entire MIB stream, it's up to the caller to filter the stream:

    while ((rc = get_mib2(&sigar->mib2, &op, &data, &len)) == GET_MIB2_OK) {
        mib2_ipNetToMediaEntry_t *entry;
        size_t size = sizeof(*entry); /* see solaris_sigar.c for the proper value of size */
        char *end;

        if (op->level != MIB2_IP) { /* checking for the IP MIB */
            continue;
        }

        if (op->name != MIB2_IP_MEDIA) { /* checking for ipNetToMediaEntry */
            continue;
        }

        for (entry = (mib2_ipNetToMediaEntry_t *)data, end = data + len;
             (char *)entry < end;
             nread+=size, entry = (mib2_ipNetToMediaEntry_t *)((char *)data+nread))
        {
            /* do what you will with entry */
        }
    }

#### Notes

* For binary compatibility, use `((mib2_ip_t *)data)->ipRouteEntrySize` rather than `sizeof(*entry)`.  This is also why we cast `(char *)data` and increment by `nbytes`, as the `sizeof(mib2_ipNetToMediaEntry_t)` differs between Solaris versions.

### Windows

Using Bing at msdn.microsoft.com, we land at the `GetIpNetTable()` function.  "The GetIpNetTable function retrieves the IPv4 to physical address mapping table.":

    DWORD GetIpNetTable(
        PMIB_IPNETTABLE pIpNetTable,
        PULONG pdwSize,
        BOOL bOrder);

Where the `MIB_IPNETTABLE` structure contains "a pointer to a table of arp entries implemented as an array of `MIB_IPNETROW` structures." and `MIB_IPNETROW` consists of:

    typedef struct _MIB_IPNETROW {
        DWORD dwIndex;
        DWORD dwPhysAddrLen;
        BYTE  bPhysAddr[MAXLEN_PHYSADDR];
        DWORD dwAddr;
        DWORD dwType;
    } MIB_IPNETROW, *PMIB_IPNETROW;

Iterate over this table using something along the lines of:

    DWORD rc, size=0, i;
    PMIB_IPNETTABLE ipnet;

    /* get the size of the table */
    rc = GetIpNetTable(null, &size, false);
    if (rc != ERROR_INSUFFICIENT_BUFFER) {
        return GetLastError();
    }
    ipnet = malloc(size); /* allocate the table */
    rc = GetIpNetTable(ipnet, &size, false);
    if (rc) {
        free(ipnet);
        return GetLastError();
    }

    for (i = 0; i < ipnet->dwNumEntries; i++) {
        PMIB_IPNETROW entry = &ipnet->table[i];
        /* do what you will with entry */
    }

#### Notes

* A newer version of this function `GetIpNetTable2()` was introducted in Vista/2008 Server

### NetBSD

See: FreeBSD

### OpenBSD

See: FreeBSD

### Author

[Doug MacEachern](http://dougm.github.com/sigar/)
