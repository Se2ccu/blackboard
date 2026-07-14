/*
 * vuln_udp_server.c - 带"异常数据包处理漏洞"的 UDP 服务（靶场）
 *
 * 设计：
 *   1) 监听 UDP 端口（默认 9090），回显收到的包
 *   2) 正常包：直接回显
 *   3) 漏洞触发点：
 *      - payload 以 "OVERFLOW:" 开头 -> vulnerable_parse() 把尾部直接拷进
 *        定长栈缓冲区，超长即越界写 -> abort()（模拟栈溢出崩溃）
 *      - payload == "MAGIC:CRASH"    -> vulnerable_parse() 在校验逻辑里
 *        对空指针解引用 -> abort()（模拟空指针崩溃）
 *
 *   崩溃发生在用户态 vulnerable_parse() 内部，可被 strace/bpftrace/
 *   coredump 捕获。靶场目的是让 PoC 验证流程能"发包 -> 抓 trace ->
 *   定位崩溃函数 -> 验证 PoC 成功"。
 *
 * 编译：
 *   gcc -O0 -g -Wall -o vuln_udp_server vuln_udp_server.c
 *   (-O0 -g 保留调试信息，便于符号化到行号)
 *
 * 用法：
 *   ./vuln_udp_server [port]            默认端口 9090
 *
 * 正常发包：
 *   printf "hello" | nc -u -w1 127.0.0.1 9090
 * 触发崩溃：
 *   printf "OVERFLOW:AAAAAAAAA...（>256 字节）" | nc -u -w1 127.0.0.1 9090
 *   printf "MAGIC:CRASH"                  | nc -u -w1 127.0.0.1 9090
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* 模拟有漏洞的定长栈缓冲区。OVERFLOW 尾部超过此长度即越界。 */
#define VULN_BUF_SIZE 64

static volatile sig_atomic_t g_stop = 0;
/* 每处理一个包自增，便于 trace 关联。 */
static uint64_t g_seq = 0;

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

/*
 * 漏洞函数：在用户态处理 UDP 包内容。
 * 这是 PoC 验证要打到的目标函数。
 *
 * 返回 0 = 正常处理；返回 -1 = 崩溃（进程实际会 abort，不会 return）。
 */
static int vulnerable_parse(const char *data, size_t len)
{
    char buf[VULN_BUF_SIZE];

    /* 打印进入点，便于 bpftrace/strace 定位崩溃函数 */
    printf("[vuln_parse] seq=%llu entered, len=%zu data=\"%.*s\"\n",
           (unsigned long long)g_seq, len, (int)(len > 64 ? 64 : len), data);
    fflush(stdout);

    /* 漏洞 1：MAGIC:CRASH -> 空指针解引用 */
    if (len == 11 && memcmp(data, "MAGIC:CRASH", 11) == 0) {
        printf("[vuln_parse] seq=%llu hit NULL-deref path (MAGIC:CRASH)\n",
               (unsigned long long)g_seq);
        fflush(stdout);
        volatile char *p = NULL;
        /* 触发 SIGSEGV，可被 trace/coredump 捕获 */
        *p = 'X';
        /* 不会到达 */
        return -1;
    }

    /* 漏洞 2：OVERFLOW:... -> 栈缓冲区越界写 */
    if (len >= 9 && memcmp(data, "OVERFLOW:", 9) == 0) {
        const char *tail = data + 9;
        size_t tail_len = len - 9;
        printf("[vuln_parse] seq=%llu hit overflow path, tail_len=%zu\n",
               (unsigned long long)g_seq, tail_len);
        fflush(stdout);
        /*
         * 有漏洞的拷贝：没有检查 tail_len 是否超过 buf 容量。
         * 超长时越界写栈，用 abort() 让崩溃可控（避免真实栈破坏
         * 导致不可预测行为，同时保留"在 vulnerable_parse 内崩溃"
         * 的特征供 trace 定位）。
         */
        memcpy(buf, tail, tail_len);
        buf[tail_len < VULN_BUF_SIZE ? tail_len : VULN_BUF_SIZE - 1] = '\0';
        if (tail_len >= VULN_BUF_SIZE) {
            printf("[vuln_parse] seq=%llu overflow triggered, aborting\n",
                   (unsigned long long)g_seq);
            fflush(stdout);
            abort();
        }
        return 0;
    }

    /* 正常路径：截断拷贝并回显 */
    size_t copy_len = len < VULN_BUF_SIZE ? len : VULN_BUF_SIZE - 1;
    memcpy(buf, data, copy_len);
    buf[copy_len] = '\0';
    return 0;
}

int main(int argc, char **argv)
{
    uint16_t port = 9090;
    if (argc >= 2) {
        long p = strtol(argv[1], NULL, 10);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "invalid port: %s\n", argv[1]);
            return 1;
        }
        port = (uint16_t)p;
    }

    /* 打印 PID 便于 bpftrace 按进程过滤 */
    printf("[vuln_udp_server] pid=%ld port=%u\n", (long)getpid(), port);
    printf("[vuln_udp_server] crash triggers: OVERFLOW:<long> / MAGIC:CRASH\n");
    fflush(stdout);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    signal(SIGINT, on_sigint);

    char buf[2048];
    printf("[vuln_udp_server] waiting for packets on 0.0.0.0:%u ...\n", port);
    fflush(stdout);

    while (!g_stop) {
        struct sockaddr_in peer = {0};
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR) {
                if (g_stop) break;
                continue;
            }
            perror("recvfrom");
            break;
        }
        buf[n] = '\0';
        ++g_seq;

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));

        printf("[vuln_udp_server] #%-4llu from %s:%u len=%zd data=\"%.*s\"\n",
               (unsigned long long)g_seq,
               ip, ntohs(peer.sin_port), n, (int)n, buf);
        fflush(stdout);

        /* 调用有漏洞的解析函数；崩溃会在此发生 */
        int rc = vulnerable_parse(buf, (size_t)n);

        if (rc != 0) {
            /* 正常不会到这里（崩溃已 abort） */
            printf("[vuln_udp_server] #%-4llu parse returned %d\n",
                   (unsigned long long)g_seq, rc);
            fflush(stdout);
        }

        /* 回显（仅正常路径会到达） */
        if (sendto(fd, buf, (size_t)n, 0,
                   (struct sockaddr *)&peer, plen) < 0) {
            perror("sendto");
        }
    }

    printf("[vuln_udp_server] exiting, total=%llu\n", (unsigned long long)g_seq);
    close(fd);
    return 0;
}
