#include "src/edfs.h"

int main() {
    // initialize edwork
    struct edfs *edfs_context = edfs_create_context(NULL);
    edfs_edwork_init(edfs_context, 4848);
    edfs_edwork_wait_initialization(edfs_context, 3000);
   
    // example for read file
    EDFS_FILE *f = ed_fopen(edfs_context, "sintaxa.txt", "r");
    if (f) {
        char buf[8192];
        int size = ed_fread(buf, 1, sizeof(buf), f);
        if (size > 0) {
            fwrite(buf, size, 1, stdout);
        }
        ed_fclose(f);
    } else
        perror("ed_fopen");

    // example for read dir & stat
    EDFS_DIR *dir = ed_opendir(edfs_context, "/");
    if (dir) {
        struct dirent *pdir;
        while ((pdir = ed_readdir(dir)) != NULL) {
            edfs_stat stbuf;
            ed_stat(edfs_context, pdir->d_name, &stbuf);
            if (stbuf.st_mode & S_IFDIR)
                fprintf(stdout, "[%s]\n", pdir->d_name);
            else
                fprintf(stdout, "%s\n", pdir->d_name);
        }

        ed_closedir(dir);
    } else
        perror("ed_opendir");

    // standard deinitialization //
    edfs_edwork_done(edfs_context);
    edfs_destroy_context(edfs_context);
}
