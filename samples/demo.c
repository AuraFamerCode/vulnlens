#include <string.h>

int handle_packet(struct conn *c, const char *payload, size_t len) {
    char name[32];
    char *buf = malloc(c->count * c->item_size);
    if (!buf)
        return -1;
    strcpy(name, payload);              /* attacker controls payload */
    memcpy(buf, payload + 4, len);      /* len never checked */
    for (int i = 0; i <= c->count; i++)
        buf[i + 1] = name[i];
    printf(name);
    free(buf);
    log_packet(c, buf);
    return 0;
}

static int copy_name(char *dst, size_t dst_len, const char *src) {
    if (dst == NULL || src == NULL || dst_len == 0)
        return -1;
    size_t n = strnlen(src, dst_len - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
    return (int)n;
}
