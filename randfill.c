// randfill.c
// Cross-platform tool to overwrite files with strong random bytes.
// Usage: randfill <path> [<path> ...]
// Supports directories (recursive) and files. Prints "Corrupting: <path>" then "Done."

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
#pragma comment(lib, "bcrypt")
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#endif

// Simple dynamic array for strings
typedef struct {
    char **items;
    size_t count;
    size_t cap;
} strvec;

static void sv_init(strvec *v) { v->items = NULL; v->count = v->cap = 0; }
static void sv_push(strvec *v, char *s) {
    if (v->count == v->cap) {
        size_t n = v->cap ? v->cap * 2 : 16;
        char **t = realloc(v->items, n * sizeof(char*));
        if (!t) { perror("realloc"); exit(1); }
        v->items = t; v->cap = n;
    }
    v->items[v->count++] = s;
}
static void sv_free(strvec *v) {
    for (size_t i=0;i<v->count;i++) free(v->items[i]);
    free(v->items);
    v->items = NULL; v->count = v->cap = 0;
}

// Get top-level path component used as sort key
// For Windows absolute paths like "C:\dir\file" -> "C:"; for UNC \\? treat first component
static char *top_component(const char *path) {
    if (!path) return NULL;
    // copy path for tokenizing
    char *p = strdup(path);
    if (!p) return NULL;
#if defined(_WIN32)
    // If path starts with drive letter "C:\..." return "C:"
    if (strlen(p) >= 2 && p[1] == ':') {
        p[2] = '\0';
        return p;
    }
    // If begins with "\\", skip leading slashes and take first component
    char *s = p;
    while (*s == '\\' || *s == '/') s++;
    char *sep = strpbrk(s, "\\/");
    if (sep) *sep = '\0';
    return s;
#else
    // For POSIX, strip leading '/', then take first component
    char *s = p;
    if (s[0] == '/') s++;
    char *sep = strchr(s, '/');
    if (sep) *sep = '\0';
    return s;
#endif
}

// Case-insensitive compare for sorting keys
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

// Helper to get file size and whether path is regular file
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
// Windows: fill buffer with cryptographic random bytes using BCryptGenRandom
static int platform_random_bytes(uint8_t *buf, size_t len) {
    if (len == 0) return 1;
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 1 : 0;
}
#else
// POSIX: read from /dev/random
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

// Overwrite file with random bytes of same size
static int corrupt_file(const char *path) {
    uint64_t size;
    if (!is_regular_file_and_size(path, &size)) return 0;
    printf("Corrupting: %s\n", path);
    if (size == 0) { printf("Done.\n"); return 1; }
#if defined(_WIN32)
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { perror("CreateFile"); return 0; }
    LARGE_INTEGER li;
    li.QuadPart = 0;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) { CloseHandle(h); perror("SetFilePointerEx"); return 0; }
    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { CloseHandle(h); return 0; }
    uint64_t remain = size;
    while (remain) {
        size_t towrite = (remain > CHUNK) ? CHUNK : (size_t)remain;
        if (!platform_random_bytes(buf, towrite)) { free(buf); CloseHandle(h); return 0; }
        DWORD written = 0;
        if (!WriteFile(h, buf, (DWORD)towrite, &written, NULL) || written != towrite) { free(buf); CloseHandle(h); return 0; }
        remain -= towrite;
    }
    free(buf);
    CloseHandle(h);
#else
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror("open"); return 0; }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) { close(fd); perror("lseek"); return 0; }
    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { close(fd); return 0; }
    uint64_t remain = size;
    while (remain) {
        size_t towrite = (remain > CHUNK) ? CHUNK : (size_t)remain;
        if (!platform_random_bytes(buf, towrite)) { free(buf); close(fd); return 0; }
        size_t off = 0;
        while (off < towrite) {
            ssize_t w = write(fd, buf + off, towrite - off);
            if (w <= 0) {
                if (errno == EINTR) continue;
                free(buf); close(fd); return 0;
            }
            off += (size_t)w;
        }
        remain -= towrite;
    }
    free(buf);
    fsync(fd);
    close(fd);
#endif
    printf("Done.\n");
    return 1;
}

// Recursively collect files from a directory
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
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collect_files_recursive(path, out);
        } else {
            sv_push(out, _strdup(path));
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(root);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        size_t n = strlen(root) + 1 + strlen(ent->d_name) + 2;
        char *path = malloc(n);
        if (!path) continue;
        snprintf(path, n, "%s/%s", root, ent->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            collect_files_recursive(path, out);
            free(path);
        } else {
            sv_push(out, path);
        }
    }
    closedir(d);
#endif
}

// Normalize separators and get a printable path copy
static char *dup_path(const char *p) {
    return strdup(p);
}

// Compare function using top component then full path
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
    free(ka);
    free(kb);
    return r;
}

static void print_help(const char *prog) {
    printf("Usage: %s <file_or_dir> [<file_or_dir> ...]\n", prog);
    printf("Overwrite each target file with strong random bytes (reads from /dev/random on Unix, system RNG on Windows).\n");
    printf("If a directory is given it will be processed recursively.\n");
    printf("Options:\n  -h, --help    Show this help message\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { print_help(argv[0]); return 1; }
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { print_help(argv[0]); return 0; }
    }

    strvec collected;
    sv_init(&collected);

    // For each argument, if it's a directory collect recursively; if file, add directly
    for (int i=1;i<argc;i++) {
        const char *p = argv[i];
#if defined(_WIN32)
        DWORD attr = GetFileAttributesA(p);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            // not existing -> skip silently
            continue;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            collect_files_recursive(p, &collected);
        } else {
            sv_push(&collected, _strdup(p));
        }
#else
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files_recursive(p, &collected);
        } else if (S_ISREG(st.st_mode)) {
            sv_push(&collected, dup_path(p));
        }
#endif
    }

    if (collected.count == 0) { return 0; }

    // Sort by top component then path
    qsort(collected.items, collected.count, sizeof(char*), cmp_paths);

    // Process files in order
    for (size_t i=0;i<collected.count;i++) {
        corrupt_file(collected.items[i]);
    }

    sv_free(&collected);
    return 0;
}
