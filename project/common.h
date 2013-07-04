#include <dirent.h>

#define SAVEFDS_DEFAULT_SAVE_FILENAME "filedescriptors"
#define ___VERSION___ "1.0"

typedef struct {
  int fd;
  char filename[NAME_MAX];
  off_t offset;
  int flags;
} savefds_fd_t;

