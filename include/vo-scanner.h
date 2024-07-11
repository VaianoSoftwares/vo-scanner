#pragma once

#include <stdio.h>

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_SERVER_PORT 4316

#define NMIN_COM 1
#define NMAX_COM 255
#define INVALID_COM_NUM 0
#define COM_PORT_FORMAT "\\\\.\\COM%hhu"

#define LOGIN_MSG_FMT "POST /api/v1/users/user/login HTTP/1.1\r\n"        \
                      "Host: %s\r\n"                                      \
                      "Content-Type: application/json; charset=utf-8\r\n" \
                      "Content-Length: %zd\r\n\r\n"                       \
                      "%s"
#define LOGIN_BODY_FMT "{\"username\":\"%s\",\"password\":\"%s\"}"

#define TIMBRA_MSG_FMT "POST /api/v1/badges/archivio HTTP/1.1\r\n"                                          \
                       "Host: %s\r\n"                                                                       \
                       "Cookie: %s\r\n"                                                                     \
                       "Content-Type: multipart/form-data; boundary=--------------------01234567890123\r\n" \
                       "Content-Length: %zd\r\n\r\n"                                                        \
                       "------------------------------01234567890123\r\n"                                   \
                       "Content-Disposition: form-data; name=\"file\"; filename=\"tmp.txt\"\r\n"            \
                       "Content-Type: text/plain\r\n\r\n"                                                   \
                       "%s"                                                                                 \
                       "-----------------------------01234567890123\r\n"
#define TIMBRA_EMPTY_BODY_LEN 184

#define NMAX_CONN_TRIES 10
#define UNAUTHORIZED_STATUS_CODE 401
#define FORBIDDEN_STATUS_CODE 403
#define SUCCESS_STATUS_CODE 200

#define TIMBRA_LOG_FILENAME "data\\timbrature.txt"
#define COOKIES_FILENAME "data\\cookies.txt"
#define SCAN_BUF_SIZE 15

typedef struct ThreadParams
{
    char *hostname;
    uint16_t port;
    char *password;
} ThreadParams;

uint8_t find_serial_port(HANDLE *hcom);
uint8_t open_serial_port(HANDLE *hcom, DWORD *event_mask);
void close_com(HANDLE *hcom);
BOOL read_scanner(HANDLE hcom, DWORD event_mask, char *buf, size_t size);
char *timestamp(void);
void show_certs(SSL *ssl);
SSL_CTX *init_CTX(void);
SOCKET conn_to_server(const char *hostname, uint16_t port);
void send_timbra_reqs(void *tparams);
void timbra_logger(const uint32_t postazione_id);
BOOL get_cookies(char *buf, size_t size);
BOOL save_cookies(char *src, size_t src_size, char *dest, size_t dest_size);
BOOL read_timbra_log(char *buf, size_t size);
uint16_t get_response_status(char *res);