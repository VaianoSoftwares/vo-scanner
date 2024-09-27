/* vo-scanner.h */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define print_err(fmt, ...)                                   \
    do                                                        \
    {                                                         \
        fprintf(stderr, "%s:%d:%s(): " fmt "\n",              \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)

#define throw_err(fmt, ...)                                   \
    do                                                        \
    {                                                         \
        fprintf(stderr, "%s:%d:%s(): " fmt "\n",              \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        exit(GetLastError());                                 \
    } while (0)

#define print_debug(fmt, ...)                                 \
    do                                                        \
    {                                                         \
        fprintf(stderr, "[DEBUG]%s:%d:%s(): " fmt "\n",       \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_SERVER_PORT 4317

#ifndef NMIN_COM
#define NMIN_COM 1
#endif /* NMIN_COM */
#define NMAX_COM 255
#define INVALID_COM_NUM 0
#define COM_PORT_FORMAT "\\\\.\\COM%hhu"

#define LOGIN_MSG_FMT "POST /api/v1/users/login HTTP/1.1\r\n"             \
                      "Host: %s\r\n"                                      \
                      "User-Agent: %s\r\n"                                \
                      "Content-Type: application/json; charset=utf-8\r\n" \
                      "Content-Length: %zd\r\n\r\n"                       \
                      "%s"
#define LOGIN_BODY_FMT "{\"name\":\"%s\",\"password\":\"%s\"}"

#define TIMBRA_MSG_FMT "POST /api/v1/archivio/timbra/badges HTTP/1.1\r\n"  \
                       "Host: %s\r\n"                                      \
                       "User-Agent: %s\r\n"                                \
                       "Cookie: %s\r\n"                                    \
                       "Content-Type: application/json; charset=utf-8\r\n" \
                       "Content-Length: %zd\r\n\r\n"                       \
                       "%s"

#define NMAX_CONN_TRIES 10
#define CLIENT_ERROR_STATUS_CODE 400
#define UNAUTHORIZED_STATUS_CODE 401
#define FORBIDDEN_STATUS_CODE 403
#define SERVER_ERROR_STATUS_CODE 500
#define SUCCESS_STATUS_CODE 200

#define TIMBRA_LOG_FILENAME "data\\timbrature.json"
#define COOKIES_FILENAME "data\\cookies.txt"
#define SCAN_BUF_SIZE 15
#define TIMBRA_LOG_ROW_FMT "{\"badge_cod\":\"%s\",\"post_id\":%u,\"created_at\":\"%s\"},"

typedef struct ThreadParams
{
    char *hostname;
    uint16_t port;
    char *password;
    char *user_agent;
} ThreadParams;

uint8_t find_serial_port(HANDLE *hcom);
uint8_t open_serial_port(HANDLE *hcom, DWORD *event_mask);
void close_com(HANDLE *hcom);
BOOL read_scanner(HANDLE hcom, DWORD event_mask, char *buf, size_t size);
void timestamp(char *buf);
void show_certs(SSL *ssl);
SSL_CTX *init_CTX(void);
SOCKET conn_to_server(const char *hostname, const uint16_t port);
void *send_timbra_reqs(void *tparams);
void timbra_logger(const uint32_t postazione_id);
BOOL get_cookies(char *buf, size_t size);
BOOL save_cookies(char *src, size_t src_size, char *dest, size_t dest_size);
BOOL read_timbra_log(char *buf, size_t size);
uint16_t get_response_status(char *res);
BOOL empty_timbra_log(void);
int main(int argc, char **argv);