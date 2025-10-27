#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <libloaderapi.h>
#pragma comment(lib, "bcrypt")
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#endif

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} strvec;

static void sv_init(strvec *v) { v->items = NULL; v->count = v->cap = 0; }
static void sv_push(strvec *v, char *s) {
    if (!s) return;
    if (v->count == v->cap) {
        size_t n = v->cap ? v->cap * 2 : 16;
        char **t = realloc(v->items, n * sizeof(char*));
        if (!t) {
            perror("realloc");
            free(s);
            exit(1);
        }
        v->items = t;
        v->cap = n;
    }
    v->items[v->count++] = s;
}
static void sv_free(strvec *v) {
    for (size_t i=0;i<v->count;i++) free(v->items[i]);
    free(v->items);
    v->items = NULL; v->count = v->cap = 0;
}

static char *top_component(const char *path) {
    if (!path) return NULL;
#if defined(_WIN32)
    if (strlen(path) >= 2 && path[1] == ':') {
        char *result = malloc(3);
        if (!result) return NULL;
        result[0] = path[0];
        result[1] = ':';
        result[2] = '\0';
        return result;
    }
    const char *s = path;
    while (*s == '\\' || *s == '/') s++;
    const char *sep = strpbrk(s, "\\/");
    if (sep) {
        size_t len = sep - s;
        char *result = malloc(len + 1);
        if (!result) return NULL;
        memcpy(result, s, len);
        result[len] = '\0';
        return result;
    }
    return strdup(s);
#else
    const char *s = path;
    if (s[0] == '/') s++;
    const char *sep = strchr(s, '/');
    if (sep) {
        size_t len = sep - s;
        char *result = malloc(len + 1);
        if (!result) return NULL;
        memcpy(result, s, len);
        result[len] = '\0';
        return result;
    }
    return strdup(s);
#endif
}

static int ci_cmp(const char *a, const char *b) {
    for (;; a++, b++) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if ('A' <= ca && ca <= 'Z') ca += 'a' - 'A';
        if ('A' <= cb && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb) return (int)ca - (int)cb;
        if (!ca) return 0;
    }
}

static int is_regular_file_and_size(const char *path, uint64_t *size_out) {
#if defined(_WIN32)
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return 0;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
    LARGE_INTEGER li;
    li.HighPart = fad.nFileSizeHigh;
    li.LowPart = fad.nFileSizeLow;
    if (size_out) *size_out = (uint64_t)li.QuadPart;
    return 1;
#else
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if (size_out) *size_out = (uint64_t)st.st_size;
    return 1;
#endif
}

#if defined(_WIN32)
static int platform_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) return 1;
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 1 : 0;
}
#else
static int platform_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) return 1;
    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) return 0;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r <= 0) {
            if (errno == EINTR) continue;
            close(fd);
            return 0;
        }
        off += (size_t)r;
    }
    close(fd);
    return 1;
}
#endif

static char *program_self_path = NULL;

static void init_self_path(char **argv) {
    if (program_self_path) return;
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf)) {
        program_self_path = strdup(buf);
        if (program_self_path) {
            for (char *p = program_self_path; *p; p++) {
                if (*p == '\\') *p = '/';
            }
        }
    }
#else
    program_self_path = realpath("/proc/self/exe", NULL);
    if (!program_self_path && argv && argv[0]) {
        program_self_path = realpath(argv[0], NULL);
    }
#endif
}

static int is_self_file(const char *path) {
    if (!program_self_path || !path) return 0;
    char *normalized_path = strdup(path);
    if (!normalized_path) return 0;
    for (char *p = normalized_path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
    int result = (strcmp(normalized_path, program_self_path) == 0);
    free(normalized_path);
    return result;
}

static char *dup_path_display(const char *p) {
    if (!p) return NULL;
    char *result = malloc(strlen(p) + 1);
    if (!result) return NULL;
    char *dst = result;
    const char *src = p;
    int last_was_backslash = 0;
    while (*src) {
        if (*src == '\\') {
            if (!last_was_backslash) {
                *dst++ = *src;
            }
            last_was_backslash = 1;
        } else {
            *dst++ = *src;
            last_was_backslash = 0;
        }
        src++;
    }
    *dst = '\0';
    return result;
}

static int corrupt_file(const char *path) {
    uint64_t size;
    if (!is_regular_file_and_size(path, &size)) {
        fprintf(stderr, "Error: Cannot access file or not a regular file: %s\n", path);
        return 0;
    }
    char *display_path = dup_path_display(path);
    if (!display_path) {
        fprintf(stderr, "Error: Memory allocation failed for path: %s\n", path);
        return 0;
    }
    printf("Corrupting: %s\n", display_path);
    free(display_path);
    if (size == 0) { printf("Done.\n"); return 1; }

#if defined(_WIN32)
    HANDLE h = CreateFileA(path, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { 
        fprintf(stderr, "Error: Cannot open file for writing: %s (error %lu)\n", path, GetLastError());
        return 0; 
    }
    
    FILETIME creation, last_access, last_write;
    if (!GetFileTime(h, &creation, &last_access, &last_write)) { 
        fprintf(stderr, "Error: Cannot get file times: %s (error %lu)\n", path, GetLastError());
        CloseHandle(h); 
        return 0; 
    }
    
    LARGE_INTEGER li;
    li.QuadPart = 0;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) { 
        fprintf(stderr, "Error: Cannot seek to file beginning: %s (error %lu)\n", path, GetLastError());
        CloseHandle(h); 
        return 0; 
    }
    
    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { 
        fprintf(stderr, "Error: Memory allocation failed for buffer: %s\n", path);
        CloseHandle(h); 
        return 0; 
    }
    
    int success = 1;
    uint64_t remain = size;
    while (remain > 0) {
        size_t towrite = (remain > CHUNK) ? CHUNK : (size_t)remain;
        if (!platform_random_bytes(buf, towrite)) { 
            fprintf(stderr, "Error: Cannot generate random data: %s\n", path);
            success = 0;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(h, buf, (DWORD)towrite, &written, NULL) || written != towrite) { 
            fprintf(stderr, "Error: Cannot write to file: %s (error %lu)\n", path, GetLastError());
            success = 0;
            break;
        }
        remain -= towrite;
    }
    free(buf);
    
    if (success) {
        if (!SetFileTime(h, &creation, &last_access, &last_write)) { 
            fprintf(stderr, "Warning: Cannot restore file times: %s (error %lu)\n", path, GetLastError());
        }
    }
    CloseHandle(h);
#else
    struct stat st;
    if (stat(path, &st) != 0) { 
        fprintf(stderr, "Error: Cannot get file info: %s (%s)\n", path, strerror(errno));
        return 0; 
    }
    
    int fd = open(path, O_WRONLY);
    if (fd < 0) { 
        fprintf(stderr, "Error: Cannot open file for writing: %s (%s)\n", path, strerror(errno));
        return 0; 
    }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) { 
        fprintf(stderr, "Error: Cannot seek to file beginning: %s (%s)\n", path, strerror(errno));
        close(fd); 
        return 0; 
    }
    
    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { 
        fprintf(stderr, "Error: Memory allocation failed for buffer: %s\n", path);
        close(fd); 
        return 0; 
    }
    
    int success = 1;
    uint64_t remain = size;
    while (remain > 0) {
        size_t towrite = (remain > CHUNK) ? CHUNK : (size_t)remain;
        if (!platform_random_bytes(buf, towrite)) { 
            fprintf(stderr, "Error: Cannot generate random data: %s\n", path);
            success = 0;
            break;
        }
        size_t off = 0;
        while (off < towrite) {
            ssize_t w = write(fd, buf + off, towrite - off);
            if (w <= 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "Error: Cannot write to file: %s (%s)\n", path, strerror(errno));
                success = 0;
                break;
            }
            off += (size_t)w;
        }
        if (!success) break;
        remain -= towrite;
    }
    free(buf);
    
    if (success) {
        fsync(fd);
        close(fd);
        
        struct utimbuf times;
        times.actime = st.st_atime;
        times.modtime = st.st_mtime;
        if (utime(path, &times) != 0) { 
            fprintf(stderr, "Warning: Cannot restore file times: %s (%s)\n", path, strerror(errno));
        }
    } else {
        close(fd);
    }
#endif
    
    if (success) {
        printf("Done.\n");
    } else {
        fprintf(stderr, "Failed to corrupt file: %s\n", path);
    }
    return success;
}

static void collect_files_recursive(const char *root, strvec *out) {
#if defined(_WIN32)
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", root);
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        const char *name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", root, name);
        if (is_self_file(path)) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collect_files_recursive(path, out);
        } else {
            sv_push(out, strdup(path));
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(root);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        size_t n = strlen(root) + 1 + strlen(ent->d_name) + 1;
        char *path = malloc(n);
        if (!path) continue;
        snprintf(path, n, "%s/%s", root, ent->d_name);
        if (is_self_file(path)) {
            free(path);
            continue;
        }
        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            collect_files_recursive(path, out);
            free(path);
        } else if (S_ISREG(st.st_mode)) {
            sv_push(out, path);
        } else {
            free(path);
        }
    }
    closedir(d);
#endif
}

static char *dup_path(const char *p) {
    if (!p) return NULL;
    return strdup(p);
}

static int cmp_paths(const void *a, const void *b) {
    const char *pa = *(const char**)a;
    const char *pb = *(const char**)b;
    char *ka = top_component(pa);
    char *kb = top_component(pb);
    int r = 0;
    if (ka && kb) {
        r = ci_cmp(ka, kb);
        if (r == 0) r = ci_cmp(pa, pb);
    } else {
        r = ci_cmp(pa, pb);
    }
    if (ka) free(ka);
    if (kb) free(kb);
    return r;
}

static void print_help(const char *prog) {
    printf("Usage: %s <file_or_dir> [<file_or_dir> ...]\n", prog);
    printf("Overwrite each target file with strong random bytes (reads from /dev/random on Unix, system RNG on Windows).\n");
    printf("If a directory is given it will be processed recursively.\n");
    printf("Options:\n  -h, --help    Show this help message\n");
}

int main(int argc, char **argv) {
    init_self_path(argv);
    if (argc < 2) { print_help(argv[0]); return 1; }
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { 
            print_help(argv[0]); 
            if (program_self_path) free(program_self_path);
            return 0; 
        }
    }
    strvec collected;
    sv_init(&collected);
    for (int i=1;i<argc;i++) {
        const char *p = argv[i];
#if defined(_WIN32)
        DWORD attr = GetFileAttributesA(p);
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            collect_files_recursive(p, &collected);
        } else {
            if (!is_self_file(p)) {
                sv_push(&collected, strdup(p));
            }
        }
#else
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files_recursive(p, &collected);
        } else if (S_ISREG(st.st_mode)) {
            if (!is_self_file(p)) {
                sv_push(&collected, dup_path(p));
            }
        }
#endif
    }
    if (collected.count == 0) { 
        if (program_self_path) free(program_self_path);
        return 0; 
    }
    qsort(collected.items, collected.count, sizeof(char*), cmp_paths);
    
    int success_count = 0;
    int fail_count = 0;
    
    for (size_t i=0;i<collected.count;i++) {
        if (corrupt_file(collected.items[i])) {
            success_count++;
        } else {
            fail_count++;
        }
    }
    
    sv_free(&collected);
    if (program_self_path) free(program_self_path);
    
    printf("\nSummary: %d files processed successfully, %d files failed\n", success_count, fail_count);
    
    return fail_count > 0 ? 1 : 0;
}
