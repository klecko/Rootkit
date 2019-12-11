struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen; // d_reclen is the way to tell the length of this entry
    char        d_name[1]; // the struct value is actually longer than this, and d_name is variable width.
};
