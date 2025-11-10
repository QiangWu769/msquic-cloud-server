#include "tcp_ss_logger.h"
#include "quic_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <regex.h>
#include <fcntl.h>
#include <signal.h>

// 定义ss日志器的完整结构体
struct _TCP_SS_LOGGER {
    BOOLEAN Initialized;            // 是否已初始化
    BOOLEAN Enabled;                // 是否启用
    uint32_t MaxEntries;            // 最大日志条目数
    uint32_t CurrentIndex;          // 当前索引
    uint32_t TotalEntries;          // 总条目数
    TCP_SS_LOG_ENTRY* Entries;      // 日志条目数组
    CXPLAT_LOCK Lock;               // 互斥锁
    uint16_t TargetPort;            // 目标端口
    pthread_t PollingThread;        // 轮询线程
    volatile BOOLEAN Running;       // 运行标志
    BOOLEAN EnableConsoleOutput;    // 启用控制台输出
    uint32_t SamplingIntervalMs;    // 采样间隔（毫秒）
    char* LogFilePath;              // 日志文件路径
    FILE* LogFileHandle;            // 日志文件句柄
    BOOLEAN DetailedLogging;        // 是否启用详细日志
    char LastDetailLine[1024];      // 存储最后一行详细信息
};

// 用于跟踪活动连接的结构体
typedef struct {
    uint32_t SourceAddr;
    uint16_t SourcePort;
    uint32_t DestAddr;
    uint16_t DestPort;
    uint64_t FirstSeen;
    uint64_t LastSeen;
    uint32_t EventCount;
} TCP_CONNECTION_TRACKING;

#define MAX_CONNECTIONS 64
static TCP_CONNECTION_TRACKING g_ActiveConnections[MAX_CONNECTIONS];
static int g_ActiveConnectionCount = 0;
static CXPLAT_LOCK g_ConnectionLock;

// 全局日志器实例
static TCP_SS_LOGGER g_TcpSsLogger = {0};

// 工具函数
static uint64_t get_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// 确保目录存在
static void ensure_directory_exists(const char* path) {
    char dir_path[512];
    strncpy(dir_path, path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';
    
    // 查找最后一个'/'并截断获得目录路径
    char* last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        
        // 尝试创建目录（多级）
        char tmp[512];
        char *p = NULL;
        size_t len;
        
        strncpy(tmp, dir_path, sizeof(tmp));
        len = strlen(tmp);
        if (tmp[len - 1] == '/')
            tmp[len - 1] = '\0';
        
        for (p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
        }
        mkdir(tmp, 0755);
    }
}

// 将未使用的函数标记为可能未使用
#if defined(__GNUC__)
#define UNUSED_FUNCTION __attribute__((unused))
#else
#define UNUSED_FUNCTION
#endif

// 用于解析带宽字符串（如 10Mbps, 1.5Kbps 等）
UNUSED_FUNCTION
static double parse_bandwidth(const char* bw_str) {
    double value = 0;
    char unit[8] = {0};
    
    if (sscanf(bw_str, "%lf%7[^b]", &value, unit) >= 1) {
        if (strcmp(unit, "K") == 0 || strcmp(unit, "k") == 0) {
            value *= 1000;
        } else if (strcmp(unit, "M") == 0 || strcmp(unit, "m") == 0) {
            value *= 1000000;
        } else if (strcmp(unit, "G") == 0 || strcmp(unit, "g") == 0) {
            value *= 1000000000;
        }
    }
    
    return value;
}

// 更新连接跟踪
static void update_connection_tracking(TCP_SS_LOGGER *logger, TCP_SS_LOG_ENTRY *entry) {
    if (!logger || !entry) return;
    
    uint64_t current_time = entry->Timestamp;
    int i;
    BOOLEAN found = FALSE;
    
    CxPlatLockAcquire(&g_ConnectionLock);
    
    // 检查是否已存在此连接
    for (i = 0; i < g_ActiveConnectionCount; i++) {
        if ((g_ActiveConnections[i].SourceAddr == entry->SourceAddr && 
             g_ActiveConnections[i].SourcePort == entry->SourcePort &&
             g_ActiveConnections[i].DestAddr == entry->DestAddr && 
             g_ActiveConnections[i].DestPort == entry->DestPort) ||
            (g_ActiveConnections[i].SourceAddr == entry->DestAddr && 
             g_ActiveConnections[i].SourcePort == entry->DestPort &&
             g_ActiveConnections[i].DestAddr == entry->SourceAddr && 
             g_ActiveConnections[i].DestPort == entry->SourcePort)) {
            
            g_ActiveConnections[i].LastSeen = current_time;
            g_ActiveConnections[i].EventCount++;
            found = TRUE;
            break;
        }
    }
    
    // 如果是新连接且有空间，则添加
    if (!found && g_ActiveConnectionCount < MAX_CONNECTIONS) {
        i = g_ActiveConnectionCount++;
        g_ActiveConnections[i].SourceAddr = entry->SourceAddr;
        g_ActiveConnections[i].SourcePort = entry->SourcePort;
        g_ActiveConnections[i].DestAddr = entry->DestAddr;
        g_ActiveConnections[i].DestPort = entry->DestPort;
        g_ActiveConnections[i].FirstSeen = current_time;
        g_ActiveConnections[i].LastSeen = current_time;
        g_ActiveConnections[i].EventCount = 1;
        
        // 记录连接开始
        if (logger->LogFileHandle) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            
            inet_ntop(AF_INET, &entry->SourceAddr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &entry->DestAddr, dst_ip, INET_ADDRSTRLEN);
            
            fprintf(logger->LogFileHandle, 
                    "[%llu] CONNECTION ESTABLISHED: %s:%u -> %s:%u\n",
                    (unsigned long long)(current_time / 1000000), // ms
                    src_ip, entry->SourcePort, 
                    dst_ip, entry->DestPort);
            fflush(logger->LogFileHandle);
        }
    }
    
    CxPlatLockRelease(&g_ConnectionLock);
}

// 修复write_log_entry_to_file函数
static void write_log_entry_to_file(TCP_SS_LOGGER* logger, TCP_SS_LOG_ENTRY* entry) {
    if (!logger || !logger->LogFileHandle) {
        return;
    }
    
    // 获取IPv4地址字符串表示
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};
    
    // 转换为点分十进制字符串
    snprintf(src_ip, INET_ADDRSTRLEN, "%u.%u.%u.%u", 
             (entry->SourceAddr >> 24) & 0xFF,
             (entry->SourceAddr >> 16) & 0xFF,
             (entry->SourceAddr >> 8) & 0xFF,
             entry->SourceAddr & 0xFF);
    
    snprintf(dst_ip, INET_ADDRSTRLEN, "%u.%u.%u.%u", 
             (entry->DestAddr >> 24) & 0xFF,
             (entry->DestAddr >> 16) & 0xFF,
             (entry->DestAddr >> 8) & 0xFF,
             entry->DestAddr & 0xFF);
    
    // 只写入原始详细信息
    if (logger->LastDetailLine[0]) {
        fprintf(logger->LogFileHandle,
                "[%llu] %s:%u -> %s:%u RAW DATA: %s\n",
                (unsigned long long)entry->Timestamp,
                src_ip, entry->SourcePort, dst_ip, entry->DestPort,
                logger->LastDetailLine);
    }
    
    // 确保立即刷新到磁盘
    fflush(logger->LogFileHandle);
}

// 检查并关闭不活动连接
static void check_inactive_connections(TCP_SS_LOGGER *logger, uint64_t current_time, uint64_t timeout_ns) {
    if (!logger) return;
    
    CxPlatLockAcquire(&g_ConnectionLock);
    
    for (int i = 0; i < g_ActiveConnectionCount; i++) {
        // 检查是否超时
        if (current_time - g_ActiveConnections[i].LastSeen > timeout_ns) {
            // 记录连接关闭
            if (logger->LogFileHandle) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                
                inet_ntop(AF_INET, &g_ActiveConnections[i].SourceAddr, src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &g_ActiveConnections[i].DestAddr, dst_ip, INET_ADDRSTRLEN);
                
                fprintf(logger->LogFileHandle, 
                        "[%llu] CONNECTION CLOSED: %s:%u -> %s:%u (Events: %u, Duration: %llu ms)\n",
                        (unsigned long long)(current_time / 1000000), // ms
                        src_ip, g_ActiveConnections[i].SourcePort, 
                        dst_ip, g_ActiveConnections[i].DestPort,
                        g_ActiveConnections[i].EventCount,
                        (unsigned long long)((g_ActiveConnections[i].LastSeen - 
                                            g_ActiveConnections[i].FirstSeen) / 1000000));
                fflush(logger->LogFileHandle);
            }
            
            // 移除此连接 (将最后一个连接移到当前位置)
            if (i < g_ActiveConnectionCount - 1) {
                g_ActiveConnections[i] = g_ActiveConnections[g_ActiveConnectionCount - 1];
                i--; // 重新检查当前位置
            }
            g_ActiveConnectionCount--;
        }
    }
    
    CxPlatLockRelease(&g_ConnectionLock);
}

// 将IPv4地址字符串转换为32位整数
static uint32_t parse_ipv4_addr(const char* ip_str) {
    struct sockaddr_in sa;
    uint32_t addr = 0;
    
    // 只对需要的连接输出调试信息
    // printf("DEBUG: Parsing IP address: '%s'\n", ip_str ? ip_str : "NULL");
    
    if (!ip_str || !*ip_str) {
        printf("ERROR: Empty IP address string\n");
        return 0;
    }
    
    // 使用inet_pton更安全地转换IP地址
    int result = inet_pton(AF_INET, ip_str, &sa.sin_addr);
    if (result == 1) {
        // 成功解析
        addr = ntohl(sa.sin_addr.s_addr);  // 转换为主机字节序
        // 只对需要的连接输出调试信息
        // printf("DEBUG: Successfully parsed IP '%s' to %u.%u.%u.%u (0x%08X)\n", 
        //        ip_str,
        //        (addr >> 24) & 0xFF, 
        //        (addr >> 16) & 0xFF, 
        //        (addr >> 8) & 0xFF, 
        //        addr & 0xFF,
        //        addr);
    } else if (result == 0) {
        // 格式无效
        printf("ERROR: Invalid IP address format: '%s'\n", ip_str);
        
        // 尝试直接解析简单格式的x.x.x.x
        unsigned int a, b, c, d;
        if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            addr = (a << 24) | (b << 16) | (c << 8) | d;
            // 只对需要的连接输出调试信息
            // printf("DEBUG: Manually parsed IP '%s' to %u.%u.%u.%u (0x%08X)\n", 
            //        ip_str, a, b, c, d, addr);
        }
    } else {
        // 系统错误
        printf("ERROR: System error parsing IP address: '%s' (errno: %d)\n", ip_str, errno);
    }
    
    return addr;
}

// 识别BBR状态（通过启发式方法）
#if defined(__GNUC__)
__attribute__((unused))
#endif
static TCP_SS_BBR_STATE infer_bbr_state(double pacing_gain, uint32_t cwnd, double min_rtt) {
    // 防止编译器警告
    (void)min_rtt;  // 标记参数已使用，但实际不用
    
    if (pacing_gain > 1.0) {
        if (pacing_gain >= 2.0) {
            return TCP_BBR_STARTUP;
        } else {
            return TCP_BBR_PROBE_BW;
        }
    } else if (pacing_gain == 1.0) {
        if (cwnd < 10) {
            return TCP_BBR_DRAIN;
        } else {
            return TCP_BBR_PROBE_BW;
        }
    } else if (pacing_gain < 1.0) {
        return TCP_BBR_PROBE_RTT;
    }
    
    return TCP_BBR_UNKNOWN;
}

// 执行ss命令并获取TCP统计信息
static void fetch_ss_data(TCP_SS_LOGGER* logger) {
    if (!logger || !logger->Initialized) return;
    
    char cmd[256];
    // 只过滤端口4433的连接
    snprintf(cmd, sizeof(cmd), "ss -tin state established 'sport = %u or dport = %u' 2>/dev/null", 
             logger->TargetPort, logger->TargetPort);
    
    // 移除调试输出
    // printf("DEBUG: Executing command: %s\n", cmd);
    
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        // 保留错误输出，这很重要
        printf("ERROR: Failed to execute ss command\n");
        return;
    }
    
    // 删除调试计数器变量
    // int line_count = 0;
    // int connection_count = 0;
    // int detailed_count = 0;
    
    char line[1024];
    TCP_SS_LOG_ENTRY entry = {0};
    BOOLEAN parsing_connection = FALSE;
    char connection_line[1024] = {0};
    
    while (fgets(line, sizeof(line), pipe)) {
        // line_count++; // 删除计数
        
        // 删除行尾的换行符
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        
        // 跳过头部行
        if (strstr(line, "State") != NULL || line[0] == '\0' || strstr(line, "Recv-Q") != NULL) continue;
        
        // 如果是连接行（包含ESTAB或者是带有冒号和端口号的行）
        if ((strstr(line, "ESTAB") != NULL) || 
            ((strstr(line, ":") != NULL || strstr(line, "]") != NULL) && 
             !strstr(line, "rtt:") && !strstr(line, "bbr:"))) {
            
            parsing_connection = TRUE;
            // connection_count++; // 删除计数
            strncpy(connection_line, line, sizeof(connection_line) - 1);
            connection_line[sizeof(connection_line) - 1] = '\0';
            
            // 初始化新的日志条目
            memset(&entry, 0, sizeof(entry));
            entry.Timestamp = get_timestamp_ns();
            // 明确设置IsBBR为FALSE，防止memset后其他操作导致它意外变成TRUE
            entry.IsBBR = FALSE;
            
            // 解析源地址和目标地址 - 处理IPv4和IPv6格式
            char src_ip[128] = {0}, dst_ip[128] = {0};
            char src_port_str[16] = {0}, dst_port_str[16] = {0};
            uint16_t src_port = 0, dst_port = 0;
            
            // 尝试提取IPv6格式 [::ffff:x.x.x.x]:port
            if (strstr(line, "[::ffff:") != NULL) {
                // 肯定是IPv6格式的IPv4映射地址
                char *src_start = strstr(line, "[::ffff:");
                if (src_start) {
                    char *src_end = strstr(src_start, "]:");
                    if (src_end) {
                        // 提取IPv4部分 (从::ffff:后开始)
                        int ip_len = src_end - (src_start + 7);
                        if (ip_len > 0 && ip_len < 128) {
                            // 确保我们提取的仅仅是IPv4地址，没有前导冒号
                            if (src_start[7] == ':') {
                                strncpy(src_ip, src_start + 8, ip_len - 1);  // 跳过冒号
                                src_ip[ip_len - 1] = '\0';
                            } else {
                                strncpy(src_ip, src_start + 7, ip_len);
                                src_ip[ip_len] = '\0';
                            }
                            
                            // 提取端口
                            char *port_start = src_end + 2; // 跳过"]:"
                            char *space = strchr(port_start, ' ');
                            if (space) {
                                // 临时修改字符串便于提取端口
                                char port_str[16] = {0};
                                int port_len = (space - port_start) < 15 ? (space - port_start) : 15;
                                strncpy(port_str, port_start, port_len);
                                port_str[port_len] = '\0';
                                
                                src_port = (uint16_t)atoi(port_str);
                                
                                // 查找目标地址
                                char *dst_start = strstr(space + 1, "[::ffff:");
                                if (dst_start) {
                                    char *dst_end = strstr(dst_start, "]:");
                                    if (dst_end) {
                                        // 提取IPv4部分
                                        ip_len = dst_end - (dst_start + 7);
                                        if (ip_len > 0 && ip_len < 128) {
                                            // 确保我们提取的仅仅是IPv4地址，没有前导冒号
                                            if (dst_start[7] == ':') {
                                                strncpy(dst_ip, dst_start + 8, ip_len - 1);  // 跳过冒号
                                                dst_ip[ip_len - 1] = '\0';
                                            } else {
                                                strncpy(dst_ip, dst_start + 7, ip_len);
                                                dst_ip[ip_len] = '\0';
                                            }
                                            
                                            // 提取端口
                                            port_start = dst_end + 2;
                                            space = strchr(port_start, ' ');
                                            if (space) {
                                                port_len = (space - port_start) < 15 ? (space - port_start) : 15;
                                                strncpy(port_str, port_start, port_len);
                                                port_str[port_len] = '\0';
                                            } else {
                                                strncpy(port_str, port_start, 15);
                                                port_str[15] = '\0';
                                            }
                                            
                                            dst_port = (uint16_t)atoi(port_str);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // printf("DEBUG: IPv6 format - Extracted src IP: %s, port: %u, dst IP: %s, port: %u\n",
                //        src_ip, src_port, dst_ip, dst_port);
                
                // 仅对端口4433的连接进行详细日志
                if (src_port == logger->TargetPort || dst_port == logger->TargetPort) {
                    // printf("DEBUG: Connection matches target port %u\n", logger->TargetPort);
                } else {
                    // printf("DEBUG: Unexpected non-target port connection despite filter\n");
                    parsing_connection = FALSE;
                    continue;
                }
            } 
            // 标准IPv4或IPv6格式
            else {
                // 尝试提取普通IPv6格式 [xxxx:xxxx:...]:port
                char *src_start = strstr(line, "[");
                char *dst_start = NULL;
                
                if (src_start) {
                    // 可能是IPv6格式
                    char *src_end = strstr(src_start, "]:");
                    if (src_end) {
                        int len = src_end - (src_start + 1);
                        if (len > 0 && len < 128) {
                            strncpy(src_ip, src_start+1, len);
                            src_ip[len] = '\0';
                            src_port = (uint16_t)atoi(src_end+2);
                            
                            // 查找目标地址
                            dst_start = strstr(src_end+2, "[");
                            if (dst_start) {
                                char *dst_end = strstr(dst_start, "]:");
                                if (dst_end) {
                                    len = dst_end - (dst_start + 1);
                                    if (len > 0 && len < 128) {
                                        strncpy(dst_ip, dst_start+1, len);
                                        dst_ip[len] = '\0';
                                        dst_port = (uint16_t)atoi(dst_end+2);
                                    }
                                }
                            }
                        }
                    }
                } 
                // 尝试标准IPv4格式解析
                else {
                    // 尝试不同的格式解析
                    if (sscanf(line, "%*s %*s %127[^:]:%15s %127[^:]:%15s", 
                              src_ip, src_port_str, dst_ip, dst_port_str) == 4) {
                        // 转换端口号
                        src_port = (uint16_t)atoi(src_port_str);
                        dst_port = (uint16_t)atoi(dst_port_str);
                    }
                }
                
                // printf("DEBUG: Standard format - Extracted src IP: %s, port: %u, dst IP: %s, port: %u\n",
                //        src_ip, src_port, dst_ip, dst_port);
                
                // 检查是否匹配目标端口
                if (src_port == logger->TargetPort || dst_port == logger->TargetPort) {
                    // printf("DEBUG: Connection matches target port %u\n", logger->TargetPort);
                } else {
                    // printf("DEBUG: Unexpected non-target port connection despite filter\n");
                    parsing_connection = FALSE;
                    continue;
                }
            }
            
            // 如果成功提取了IP和端口
            if (src_ip[0] && dst_ip[0]) {
                // 将IP地址转换为内部表示
                entry.SourceAddr = parse_ipv4_addr(src_ip);
                entry.DestAddr = parse_ipv4_addr(dst_ip);
                entry.SourcePort = src_port;
                entry.DestPort = dst_port;
                
                // printf("DEBUG: Found connection %s:%u -> %s:%u\n", 
                //        src_ip, src_port, dst_ip, dst_port);
            } else {
                // printf("DEBUG: Failed to extract IP and port from line: %s\n", line);
                parsing_connection = FALSE;
                continue;
            }
            
            continue;
        }
        
        // 如果正在解析连接，且下一行包含详细信息(rtt或bbr)
        if (parsing_connection && (strstr(line, "rtt:") != NULL || strstr(line, "bbr") != NULL)) {
            // detailed_count++; // 删除计数
            // printf("DEBUG: Processing detail line: %s\n", line); // 删除调试输出
            
            // 保存原始详细行以便写入日志
            strncpy(logger->LastDetailLine, line, sizeof(logger->LastDetailLine) - 1);
            logger->LastDetailLine[sizeof(logger->LastDetailLine) - 1] = '\0';
            
            // 解析RTT - 与脚本类似的方法
            if (strstr(line, "rtt:") != NULL) {
                char *rtt_info = strstr(line, "rtt:");
                if (rtt_info) {
                    char rtt_val[32] = {0};
                    char rtt_var_info[32] = {0};
                    
                    if (sscanf(rtt_info, "rtt:%[^/]/%s", rtt_val, rtt_var_info) >= 1) {
                        entry.RttMs = atof(rtt_val);
                        entry.RttVarMs = atof(rtt_var_info);
                    }
                    // printf("DEBUG: Parsed RTT: %.2f ms, var: %.2f ms\n", entry.RttMs, entry.RttVarMs);
                }
            }
            
            // 解析拥塞窗口
            if (strstr(line, "cwnd:") != NULL) {
                sscanf(strstr(line, "cwnd:"), "cwnd:%u", &entry.SndCwnd);
                // printf("DEBUG: Parsed cwnd: %u\n", entry.SndCwnd);
            }
            
            // 解析重传
            if (strstr(line, "retrans:") != NULL) {
                char retrans_current[32] = {0};
                if (sscanf(strstr(line, "retrans:"), "retrans:%[^/]/%u", retrans_current, &entry.RetransSegs) >= 1) {
                    // 可以选择保存当前重传段数
                    // printf("DEBUG: Parsed retrans segments: %u\n", entry.RetransSegs);
                }
            }
            
            // 解析丢包
            if (strstr(line, "lost:") != NULL) {
                sscanf(strstr(line, "lost:"), "lost:%u", &entry.LostPackets);
                // printf("DEBUG: Parsed lost packets: %u\n", entry.LostPackets);
            }
            
            // 解析发送速率
            if (strstr(line, "send ") != NULL) {
                char rate_str[64] = {0};
                if (sscanf(strstr(line, "send "), "send %s", rate_str) == 1) {
                    double value = 0;
                    
                    // 处理单位
                    if (strstr(rate_str, "Mbps")) {
                        value = atof(rate_str) * 1000000;
                    } else if (strstr(rate_str, "Kbps")) {
                        value = atof(rate_str) * 1000;
                    } else if (strstr(rate_str, "bps")) {
                        value = atof(rate_str);
                    }
                    
                    entry.SendRateBps = value;
                    // printf("DEBUG: Parsed send rate: %.2f bps\n", value);
                }
            }
            
            // 解析BBR状态和参数
            if (strstr(line, "bbr:") != NULL || strstr(line, "bbr(") != NULL) {
                // 检查BBR连接
                entry.IsBBR = TRUE;  // 只设置日志条目中的BBR标志
                
                // 打印整行以便调试
                // printf("DEBUG: BBR line: %s\n", line);
                
                char *bbr_start = strstr(line, "bbr:(");
                if (!bbr_start) bbr_start = strstr(line, "bbr:(");
                
                if (bbr_start) {
                    char bbr_info[256] = {0};
                    int len = 0;
                    
                    bbr_start += 5; // 跳过"bbr:("
                    char *bbr_end = strstr(bbr_start, ")");
                    
                    if (bbr_end) {
                        len = (bbr_end - bbr_start) < 255 ? (bbr_end - bbr_start) : 255;
                        strncpy(bbr_info, bbr_start, len);
                        bbr_info[len] = '\0';
                        
                        // 打印提取的BBR信息
                        // printf("DEBUG: Extracted BBR info: %s\n", bbr_info);
                        
                        // 解析BBR带宽
                        char bw_str[128] = {0};
                        char bw_val[64] = {0};
                        
                        if (strstr(bbr_info, "bw:") != NULL) {
                            strncpy(bw_str, strstr(bbr_info, "bw:"), sizeof(bw_str)-1);
                            
                            if (sscanf(bw_str, "bw:%[^,)]", bw_val) == 1) {
                                // 打印带宽值以便调试
                                // printf("DEBUG: Extracted BW value: %s\n", bw_val);
                                
                                // 解析带宽，处理单位
                                double value = 0;
                                
                                // 处理单位
                                if (strstr(bw_val, "Mbps")) {
                                    value = atof(bw_val) * 1000000;
                                } else if (strstr(bw_val, "Kbps")) {
                                    value = atof(bw_val) * 1000;
                                } else if (strstr(bw_val, "bps")) {
                                    value = atof(bw_val);
                                } else {
                                    // 可能没有单位，尝试直接转换
                                    value = atof(bw_val);
                                }
                                
                                entry.BbrBandwidthBps = value;
                                // printf("DEBUG: Parsed BBR bandwidth: %.2f bps\n", value);
                            }
                        }
                    }
                    
                    // 检查并设置BBR状态
                    char *pacing_gain_str = strstr(bbr_info, "pacing_gain:");
                    double pacing_gain = 0.0;
                    if (pacing_gain_str && sscanf(pacing_gain_str, "pacing_gain:%lf", &pacing_gain) == 1) {
                        entry.BbrPacingGain = pacing_gain;
                        
                        // 基于增益推断状态
                        if (pacing_gain > 1.0) {
                            entry.BbrState = TCP_BBR_PROBE_BW;
                            // printf("DEBUG: BBR state: PROBE_BW (pacing_gain > 1.0)\n");
                        } else if (pacing_gain < 1.0) {
                            entry.BbrState = TCP_BBR_PROBE_RTT;
                            // printf("DEBUG: BBR state: PROBE_RTT (pacing_gain < 1.0)\n");
                        } else {
                            entry.BbrState = TCP_BBR_PROBE_BW;
                            // printf("DEBUG: BBR state: PROBE_BW (default)\n");
                        }
                    } else {
                        entry.BbrState = TCP_BBR_PROBE_BW; // 默认状态
                    }
                }
            }
            
            // 处理收集到的数据
            if (entry.SourceAddr != 0 && entry.DestAddr != 0) {
                // printf("DEBUG: Recording valid connection from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n", 
                //        (entry.SourceAddr >> 24) & 0xFF, 
                //        (entry.SourceAddr >> 16) & 0xFF, 
                //        (entry.SourceAddr >> 8) & 0xFF, 
                //        entry.SourceAddr & 0xFF,
                //        entry.SourcePort,
                //        (entry.DestAddr >> 24) & 0xFF, 
                //        (entry.DestAddr >> 16) & 0xFF, 
                //        (entry.DestAddr >> 8) & 0xFF, 
                //        entry.DestAddr & 0xFF,
                //        entry.DestPort);
                
                CxPlatLockAcquire(&logger->Lock);
                
                // 记录日志条目
                if (logger->Entries != NULL) {
                    logger->Entries[logger->CurrentIndex] = entry;
                    logger->CurrentIndex = (logger->CurrentIndex + 1) % logger->MaxEntries;
                }
                logger->TotalEntries++;
                
                CxPlatLockRelease(&logger->Lock);
                
                // 更新连接跟踪
                update_connection_tracking(logger, &entry);
                
                // 写入日志文件
                if (logger->LogFileHandle) {
                    // printf("DEBUG: Writing to log file %p\n", logger->LogFileHandle);
                    write_log_entry_to_file(logger, &entry);
                } else {
                    // printf("ERROR: Log file handle is NULL, cannot write entry\n");
                }
                
                // 控制台输出
                if (0) { // 永远不执行
                    char src_ip_str[INET_ADDRSTRLEN] = {0};
                    char dst_ip_str[INET_ADDRSTRLEN] = {0};
                    
                    // 转换为点分十进制字符串
                    snprintf(src_ip_str, INET_ADDRSTRLEN, "%u.%u.%u.%u", 
                             (entry.SourceAddr >> 24) & 0xFF,
                             (entry.SourceAddr >> 16) & 0xFF,
                             (entry.SourceAddr >> 8) & 0xFF,
                             entry.SourceAddr & 0xFF);
                    
                    snprintf(dst_ip_str, INET_ADDRSTRLEN, "%u.%u.%u.%u", 
                             (entry.DestAddr >> 24) & 0xFF,
                             (entry.DestAddr >> 16) & 0xFF,
                             (entry.DestAddr >> 8) & 0xFF,
                             entry.DestAddr & 0xFF);
                    
                    const char* bbr_state_str = "UNKNOWN";
                    switch (entry.BbrState) {
                        case TCP_BBR_STARTUP: bbr_state_str = "STARTUP"; break;
                        case TCP_BBR_DRAIN: bbr_state_str = "DRAIN"; break;
                        case TCP_BBR_PROBE_BW: bbr_state_str = "PROBE_BW"; break;
                        case TCP_BBR_PROBE_RTT: bbr_state_str = "PROBE_RTT"; break;
                        default: break;
                    }
                    
                    printf("[%llu] TCP: %s:%u -> %s:%u | RTT: %.2fms | CWND: %u | %s | BW: %.2fMbps\n",
                           (unsigned long long)(entry.Timestamp / 1000000),
                           src_ip_str, entry.SourcePort,
                           dst_ip_str, entry.DestPort,
                           entry.RttMs,
                           entry.SndCwnd,
                           entry.IsBBR ? bbr_state_str : "NON-BBR",
                           (entry.IsBBR ? entry.BbrBandwidthBps : entry.SendRateBps) / 1000000.0);
                }
            } else {
                // printf("ERROR: Invalid source or destination address: %u, %u\n", entry.SourceAddr, entry.DestAddr);
            }
            
            parsing_connection = FALSE;
        }
    }
    
    // printf("DEBUG: SS command results - Lines: %d, Connections: %d, Detailed entries: %d\n", 
    //        line_count, connection_count, detailed_count);
    
    pclose(pipe);
    
    // 保留超时检查代码，但删除调试输出
    static uint64_t last_check_time = 0;
    uint64_t current_time = get_timestamp_ns();
    if (current_time - last_check_time > 10000000000ULL) {
        check_inactive_connections(logger, current_time, 30000000000ULL); // 30秒超时
        last_check_time = current_time;
    }
}

// 轮询线程函数
static void* polling_thread_func(void* arg) {
    TCP_SS_LOGGER* logger = (TCP_SS_LOGGER*)arg;
    
    while (logger->Running) {
        fetch_ss_data(logger);
        
        // 等待采样间隔
        usleep(logger->SamplingIntervalMs * 1000);
    }
    
    return NULL;
}

// 获取默认日志器
_IRQL_requires_max_(DISPATCH_LEVEL)
TCP_SS_LOGGER* TcpSsLoggerGetDefault(void) {
    return &g_TcpSsLogger;
}

// 初始化日志器
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
TcpSsLoggerInitialize(
    _In_ TCP_SS_LOGGER* Logger,
    _In_ uint32_t MaxLogEntries,
    _In_ uint16_t TargetPort
    )
{
    if (Logger == NULL) return QUIC_STATUS_INVALID_PARAMETER;
    
    memset(Logger, 0, sizeof(TCP_SS_LOGGER));
    Logger->MaxEntries = MaxLogEntries > 0 ? MaxLogEntries : 10000;
    Logger->TargetPort = TargetPort;
    Logger->SamplingIntervalMs = 200; // 默认采样间隔200ms
    Logger->DetailedLogging = TRUE;   // 默认启用详细日志
    Logger->EnableConsoleOutput = FALSE; // 默认禁用控制台输出
    Logger->LastDetailLine[0] = '\0';  // 确保详细行为空字符串
    CxPlatLockInitialize(&Logger->Lock);
    CxPlatLockInitialize(&g_ConnectionLock);

    // 创建日志条目数组
    Logger->Entries = (TCP_SS_LOG_ENTRY*)CxPlatAlloc(Logger->MaxEntries * sizeof(TCP_SS_LOG_ENTRY), 'gLsS');
    if (Logger->Entries == NULL) {
        CxPlatLockUninitialize(&Logger->Lock);
        CxPlatLockUninitialize(&g_ConnectionLock);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    memset(Logger->Entries, 0, Logger->MaxEntries * sizeof(TCP_SS_LOG_ENTRY));
    
    // 默认日志文件路径
    TcpSsLoggerSetLogFile(Logger, "/home/administrator/msquic-cloud-server/bbr_logs/tcpbbr.txt");
    
    Logger->Initialized = TRUE;
    return QUIC_STATUS_SUCCESS;
}

// 清理日志器
_IRQL_requires_max_(PASSIVE_LEVEL)
void TcpSsLoggerCleanup(_In_ TCP_SS_LOGGER* Logger) {
    if (Logger == NULL || !Logger->Initialized) return;
    
    TcpSsLoggerStop(Logger);
    
    // 检查所有连接并记录关闭
    uint64_t current_time = get_timestamp_ns();
    check_inactive_connections(Logger, current_time, 0); // 强制关闭所有连接
    
    if (Logger->Entries) {
        CxPlatFree(Logger->Entries, 'gLsS');
        Logger->Entries = NULL;
    }
    
    // 关闭日志文件
    if (Logger->LogFileHandle) {
        fprintf(Logger->LogFileHandle, "\n--- TCP SS Logging Stopped ---\n");
        fprintf(Logger->LogFileHandle, "Total Events: %u\n", Logger->TotalEntries);
        fclose(Logger->LogFileHandle);
        Logger->LogFileHandle = NULL;
    }
    
    if (Logger->LogFilePath) {
        free(Logger->LogFilePath);
        Logger->LogFilePath = NULL;
    }
    
    CxPlatLockUninitialize(&Logger->Lock);
    CxPlatLockUninitialize(&g_ConnectionLock);
    memset(Logger, 0, sizeof(TCP_SS_LOGGER));
}

// 启动日志记录
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS TcpSsLoggerStart(_In_ TCP_SS_LOGGER* Logger) {
    if (!Logger || !Logger->Initialized) return QUIC_STATUS_INVALID_STATE;
    if (Logger->Running) return QUIC_STATUS_SUCCESS;
    
    Logger->Running = TRUE;
    
    if (Logger->LogFileHandle) {
        fprintf(Logger->LogFileHandle, "--- TCP SS Logging Started ---\n");
        fprintf(Logger->LogFileHandle, "Timestamp format: [milliseconds since boot]\n\n");
        fflush(Logger->LogFileHandle);
    }
    
    // 创建轮询线程
    if (pthread_create(&Logger->PollingThread, NULL, polling_thread_func, Logger) != 0) {
        Logger->Running = FALSE;
        return QUIC_STATUS_INTERNAL_ERROR;
    }
    
    return QUIC_STATUS_SUCCESS;
}

// 停止日志记录
_IRQL_requires_max_(PASSIVE_LEVEL)
void TcpSsLoggerStop(_In_ TCP_SS_LOGGER* Logger) {
    if (!Logger || !Logger->Running) return;
    
    Logger->Running = FALSE;
    pthread_join(Logger->PollingThread, NULL);
}

// 打印所有日志
_IRQL_requires_max_(PASSIVE_LEVEL)
void TcpSsLoggerPrintAll(_In_ const TCP_SS_LOGGER* Logger) {
    if (!Logger || !Logger->Initialized) return;
    
    printf("\n--- TCP SS Log (Total: %u events) ---\n", Logger->TotalEntries);
    
    // 打印BBR事件统计
    uint32_t bbr_startup_events = 0;
    uint32_t bbr_drain_events = 0;
    uint32_t bbr_probe_bw_events = 0;
    uint32_t bbr_probe_rtt_events = 0;
    uint32_t bbr_unknown_events = 0;
    
    for (uint32_t i = 0; i < Logger->MaxEntries && i < Logger->TotalEntries; i++) {
        uint32_t idx = (Logger->CurrentIndex + i) % Logger->MaxEntries;
        switch (Logger->Entries[idx].BbrState) {
            case TCP_BBR_STARTUP: bbr_startup_events++; break;
            case TCP_BBR_DRAIN: bbr_drain_events++; break;
            case TCP_BBR_PROBE_BW: bbr_probe_bw_events++; break;
            case TCP_BBR_PROBE_RTT: bbr_probe_rtt_events++; break;
            default: bbr_unknown_events++; break;
        }
    }
    
    printf("BBR State Events:\n");
    printf("  STARTUP: %u\n", bbr_startup_events);
    printf("  DRAIN: %u\n", bbr_drain_events);
    printf("  PROBE_BW: %u\n", bbr_probe_bw_events);
    printf("  PROBE_RTT: %u\n", bbr_probe_rtt_events);
    printf("  UNKNOWN: %u\n", bbr_unknown_events);
    
    // 打印RTT统计
    double min_rtt = 0, max_rtt = 0, sum_rtt = 0;
    uint32_t rtt_samples = 0;
    
    for (uint32_t i = 0; i < Logger->MaxEntries && i < Logger->TotalEntries; i++) {
        uint32_t idx = (Logger->CurrentIndex + i) % Logger->MaxEntries;
        if (Logger->Entries[idx].RttMs > 0) {
            if (min_rtt == 0 || Logger->Entries[idx].RttMs < min_rtt) {
                min_rtt = Logger->Entries[idx].RttMs;
            }
            if (Logger->Entries[idx].RttMs > max_rtt) {
                max_rtt = Logger->Entries[idx].RttMs;
            }
            sum_rtt += Logger->Entries[idx].RttMs;
            rtt_samples++;
        }
    }
    
    printf("\nRTT Statistics:\n");
    if (rtt_samples > 0) {
        printf("  Min RTT: %.2f ms\n", min_rtt);
        printf("  Max RTT: %.2f ms\n", max_rtt);
        printf("  Avg RTT: %.2f ms\n", sum_rtt / rtt_samples);
        printf("  Samples: %u\n", rtt_samples);
    } else {
        printf("  No RTT data available\n");
    }
    
    // 打印重传统计
    uint32_t retrans_events = 0;
    uint32_t max_retrans = 0;
    uint64_t max_bytes_retrans = 0;
    
    for (uint32_t i = 0; i < Logger->MaxEntries && i < Logger->TotalEntries; i++) {
        uint32_t idx = (Logger->CurrentIndex + i) % Logger->MaxEntries;
        if (Logger->Entries[idx].RetransSegs > 0) {
            retrans_events++;
            if (Logger->Entries[idx].RetransSegs > max_retrans) {
                max_retrans = Logger->Entries[idx].RetransSegs;
            }
        }
        if (Logger->Entries[idx].BytesRetrans > max_bytes_retrans) {
            max_bytes_retrans = Logger->Entries[idx].BytesRetrans;
        }
    }
    
    printf("\nRetransmission Statistics:\n");
    printf("  Retransmission Events: %u\n", retrans_events);
    printf("  Max Retransmission Segments: %u\n", max_retrans);
    printf("  Max Retransmission Bytes: %lu\n", max_bytes_retrans);
}

// 设置输出选项
_IRQL_requires_max_(PASSIVE_LEVEL)
void TcpSsLoggerSetOutputOptions(
    _In_ TCP_SS_LOGGER* Logger,
    _In_ BOOLEAN EnableConsoleOutput,
    _In_ uint32_t SamplingInterval
    ) 
{
    if (!Logger) return;
    
    Logger->EnableConsoleOutput = EnableConsoleOutput;
    Logger->SamplingIntervalMs = (SamplingInterval > 0) ? SamplingInterval : 200; // 最小为10ms
}

// 设置日志文件
_IRQL_requires_max_(PASSIVE_LEVEL)
void TcpSsLoggerSetLogFile(_In_ TCP_SS_LOGGER* Logger, _In_ const char* FilePath) {
    if (Logger == NULL || FilePath == NULL) return;
    
    // 关闭现有日志文件
    if (Logger->LogFileHandle) {
        fclose(Logger->LogFileHandle);
        Logger->LogFileHandle = NULL;
    }
    
    // 释放现有路径
    if (Logger->LogFilePath) {
        CxPlatFree(Logger->LogFilePath, QUIC_POOL_PERF);
        Logger->LogFilePath = NULL;
    }
    
    // 分配新路径
    size_t path_len = strlen(FilePath);
    Logger->LogFilePath = (char*)CxPlatAlloc(path_len + 1, QUIC_POOL_PERF);
    if (!Logger->LogFilePath) return;
    
    memcpy(Logger->LogFilePath, FilePath, path_len + 1);
    
    // 确保目录存在
    ensure_directory_exists(Logger->LogFilePath);
    
    // 打开日志文件 (直接使用原始路径，不添加日期时间戳)
    Logger->LogFileHandle = fopen(Logger->LogFilePath, "a"); // 使用追加模式
    if (Logger->LogFileHandle == NULL) {
        printf("ERROR: Failed to open log file: %s (errno: %d)\n", 
               Logger->LogFilePath, errno);
        return;
    }
    
    // 写入初始化头信息
    time_t now = time(NULL);
    fprintf(Logger->LogFileHandle, "\n--- TCP SS Logger Initialized ---\n");
    fprintf(Logger->LogFileHandle, "Date: %s", ctime(&now)); // ctime会自动添加换行符
    fprintf(Logger->LogFileHandle, "\n--- TCP SS Logging Started ---\n");
    fprintf(Logger->LogFileHandle, "Timestamp format: [milliseconds since boot]\n\n");
    
    fflush(Logger->LogFileHandle);
} 