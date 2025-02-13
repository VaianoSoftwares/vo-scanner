#ifndef VO_SCANNER_H_
#define VO_SCANNER_H_

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define sizeof(x) (ptrdiff_t)sizeof(x)
#define countof(a) (sizeof(a) / sizeof(*(a)))
#define lengthof(s) (countof(s) - 1)

#ifdef max
#undef max
#endif
#define max(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#ifdef min
#undef min
#endif
#define min(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define TIMESTAMP (get_current_timestamp(timestamp, sizeof(timestamp)))

#ifndef NO_CONSOLE
#define __fprintf_err(file, fmt, ...)                                          \
    do                                                                         \
    {                                                                          \
        fprintf(file, "%s:%d:%s(): %s: " fmt "\n",                             \
                __FILE__, __LINE__, __func__, strerror(errno), ##__VA_ARGS__); \
        fflush(file);                                                          \
    } while (0)
#define __printf_err(fmt, ...)                     \
    do                                             \
    {                                              \
        __fprintf_err(stderr, fmt, ##__VA_ARGS__); \
    } while (0)
#define __fprint_err(file, cstr)                                \
    do                                                          \
    {                                                           \
        fprintf(file, "%s:%d:%s(): %s: " cstr "\n",             \
                __FILE__, __LINE__, __func__, strerror(errno)); \
        fflush(file);                                           \
    } while (0)
#define __print_err(cstr)           \
    do                              \
    {                               \
        __fprint_err(stderr, cstr); \
    } while (0)

#define __fthrowf_err(file, fmt, ...)            \
    do                                           \
    {                                            \
        __fprintf_err(file, fmt, ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                      \
    } while (0)
#define __throwf_err(fmt, ...)            \
    do                                    \
    {                                     \
        __printf_err(fmt, ##__VA_ARGS__); \
        exit(EXIT_FAILURE);               \
    } while (0)
#define __fthrow_err(file, cstr)   \
    do                             \
    {                              \
        __fprintf_err(file, cstr); \
        exit(EXIT_FAILURE);        \
    } while (0)
#define __throw_err(cstr)   \
    do                      \
    {                       \
        __print_err(cstr);  \
        exit(EXIT_FAILURE); \
    } while (0)

#define print_log(fmt, ...)         \
    do                              \
    {                               \
        printf(fmt, ##__VA_ARGS__); \
    } while (0)
#define print_err(fmt, ...) __printf_err(fmt, ##__VA_ARGS__)
#define throw_err(fmt, ...)               \
    do                                    \
    {                                     \
        __printf_err(fmt, ##__VA_ARGS__); \
        msgbox_err(fmt, ##__VA_ARGS__);   \
        exit(EXIT_FAILURE);               \
    } while (0)
#else
#define __fprintf_err(file, fmt, ...)
#define __fthrowf_err(file, fmt, ...)
#define __printf_err(fmt, ...)
#define __throwf_err(fmt, ...)
#define __fprint_err(file, cstr)
#define __fthrow_err(file, cstr)
#define __print_err(cstr)
#define __throw_err(cstr)
#define print_log
#define print_err(fmt, ...)
#define throw_err(fmt, ...)           \
    do                                \
    {                                 \
        msgbox_err(fmt, ##__VA_ARGS); \
        exit(EXIT_FAILURE);           \
    } while (0)
#endif // NO_CONSOLE

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_SERVER_PORT "443"

#ifndef NMIN_COM
#define NMIN_COM 1
#endif // NMIN_COM
#define NMAX_COM 255
#define INVALID_COM_NUM 0
#define COMM_PORT_FORMAT "\\\\.\\COM%hhu"

#define LOGIN_MSG_FMT "POST /api/v1/users/login HTTP/1.1\r\n"             \
                      "Host: %s\r\n"                                      \
                      "User-Agent: vo-scanner\r\n"                        \
                      "Content-Type: application/json; charset=utf-8\r\n" \
                      "Content-Length: %zd\r\n"                           \
                      "Connection: close\r\n"                             \
                      "\r\n"                                              \
                      "%s"
#define LOGIN_BODY_FMT "{\"name\":\"%s\",\"password\":\"%s\"}"

#define TIMBRA_MSG_FMT "POST /api/v1/archivio/timbra/badges HTTP/1.1\r\n"  \
                       "Host: %s\r\n"                                      \
                       "User-Agent: vo-scanner\r\n"                        \
                       "Cookie: %s\r\n"                                    \
                       "Content-Type: application/json; charset=utf-8\r\n" \
                       "Content-Length: %zd\r\n"                           \
                       "Connection: close\r\n"                             \
                       "\r\n"                                              \
                       "%s"

#define CLIENT_ERROR_STATUS_CODE 400
#define UNAUTHORIZED_STATUS_CODE 401
#define FORBIDDEN_STATUS_CODE 403
#define SERVER_ERROR_STATUS_CODE 500
#define SUCCESS_STATUS_CODE 200
#define ERR_STATUS_CODE -1

#define TIMBRA_LOG_FILENAME "data\\timbrature.json"
#define COOKIES_FILENAME "data\\cookies.txt"
#define TIMBRA_LOG_ROW_FMT "{\"badge_cod\":\"%s\",\"post_id\":%u,\"created_at\":\"%s\"},"

#define TIMER_ID 1
#define BEEP_IN "res\\in.wav"
#define BEEP_OUT "res\\out.wav"
#define POPUP_MSG_SUCC_FMT "Badge Timbrato con Successo\n\n%s %s %s Struttura"
#define POPUP_MSG_FAIL "Impossibile Timbrare Badge\n\nCodice Non Valido"
#define WIN_WIDTH 650
#define WIN_HEIGHT 250

#define LOG_FILENAME "logs\\"__DATE__ \
                     ".log"

typedef struct ReqsArgs
{
    char *port;
    char *hostname;
    char *password;
    char *username;
} ReqsArgs;

typedef struct LogArgs
{
    uint32_t postazione_id;
} LogArgs;

typedef enum ProgramArgsAttrs
{
    PAA_PSW,
    PAA_POSTID,
    PAA_HOST,
    PAA_PORT,
    PAA_UNAME,
    PAA_PSW1,
    PAA_UNAME1,
    PAA_HOST1
} ProgramArgsAttrs;

#define PAN_PSW

typedef struct ProgramArgs
{
    ReqsArgs reqs;
    LogArgs log;
} ProgramArgs;

typedef struct PopupInfo
{
    char inner_text[128];
    COLORREF bg_color;
    HFONT font;
    HWND hwnd;
} PopupInfo;

typedef struct ScanData
{
    char code[16];
    char name[32];
    char surname[32];
    uint8_t code_len;
    bool mark_in;
} ScanData;

typedef struct CommData
{
    HANDLE handler;
    DWORD event_mask;
    uint8_t nport;
    bool ready;
} CommData;

void *send_timbra_reqs(void *args);
void *logger_routine(void *args);
void popup_manager(void);
SSL *init_https_conn(const char *hostname, const char *port);
void show_certs(SSL *ssl);
bool send_login_req(SSL *ssl, const char *username, const char *password, const char *hostname, char *cookies, size_t cookies_size);
bool send_mark_req(SSL *ssl, const char *hostname, const char *cookies, uint16_t *status_code);
bool get_cookies(char *buf, size_t size);
bool save_cookies(char *src, char *dest, size_t dest_size);
bool read_timbra_log(char *buf, size_t size);
void write_to_timbra_log(const char *code, const uint32_t postazione_id);
bool get_response_status(char *res, uint16_t *status_code);
bool empty_timbra_log(void);
bool find_serial_port(CommData *comm);
bool open_serial_port(CommData *comm);
void close_comm(CommData *comm);
bool read_scanner(CommData *comm, char *buf, size_t size);
bool is_badge_code_valid(const char *code_str);
bool parse_scan_data(char *buf, ScanData *out);
char *get_current_timestamp(char *buf, size_t size);
LRESULT CALLBACK window_proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
ProgramArgs parse_args(int argc, char **argv);
void hide_console(void);
void msgbox_err(const char *fmt, ...);
int main(int argc, char **argv);

#endif // VO_SCANNER_H_