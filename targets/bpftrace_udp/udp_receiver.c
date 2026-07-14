/*
 * udp_receiver.c - 简单 UDP 收包程序
 *
 * 用于配合 bpftrace 进行内核 UDP 接收路径动态跟踪。
 *
 * 行为：
 *   1) 在指定端口监听 UDP
 *   2) 循环 recvfrom，打印每条消息的序号、来源、长度、内容
 *   3) 默认打印到 stdout，方便观察；同时输出 PID 便于 bpftrace 过滤
 *
 * 编译：
 *   gcc -O2 -Wall -o udp_receiver udp_receiver.c
 *
 * 用法：
 *   ./udp_receiver [port]            默认端口 9000
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

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv)
{
    uint16_t port = 9000;
    if (argc >= 2) {
        long p = strtol(argv[1], NULL, 10);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "invalid port: %s\n", argv[1]);
            return 1;
        }
        port = (uint16_t)p;
    }

    /* 打印 PID 便于 bpftrace 按进程过滤 */
    printf("[udp_receiver] pid=%ld port=%u\n", (long)getpid(), port);
    fflush(stdout);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    /* 允许地址快速复用，便于反复测试 */
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
    uint64_t seq = 0;
    printf("[udp_receiver] waiting for packets on 0.0.0.0:%u ...\n", port);
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

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));

        printf("[udp_receiver] #%-4llu from %s:%u len=%zd data=\"%s\"\n",
               (unsigned long long)++seq,
               ip, ntohs(peer.sin_port), n, buf);
        fflush(stdout);
    }

    printf("[udp_receiver] exiting, total=%llu\n", (unsigned long long)seq);
    close(fd);
    return 0;
}
