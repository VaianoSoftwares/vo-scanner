/* vo-scanner.c */

#include "vo-scanner.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t send_req_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_req_cond = PTHREAD_COND_INITIALIZER;

int main(int argc, char **argv)
{
    if (argc < 3)
        throw_err("usage: %s <password> <postazioneId> <hostname> <port>", argv[0]);

    ThreadParams tparams = {
        .hostname = argc > 3 ? argv[3] : DEFAULT_HOSTNAME,
        .port = argc > 4 ? (uint16_t)atoi(argv[4]) : DEFAULT_SERVER_PORT,
        .password = argv[1],
        .user_agent = argv[0]};

    CreateDirectory("data", NULL);

    pthread_t pid;
    if (pthread_create(&pid, NULL, send_timbra_reqs, (void *)&tparams))
        throw_err("pthread_create");

    timbra_logger((uint32_t)atoi(argv[2]));

    puts("Waiting for children.");
    pthread_join(pid, NULL);

    puts("Execution terminated.");

    return EXIT_SUCCESS;
}

void timbra_logger(const uint32_t postazione_id)
{
    HANDLE hcomm = INVALID_HANDLE_VALUE;
    DWORD event_mask;
    uint8_t ncomm = INVALID_COM_NUM;

    while (TRUE)
    {
        if (hcomm == INVALID_HANDLE_VALUE)
        {
            if (!(ncomm = open_serial_port(&hcomm, &event_mask)))
            {
                print_err("open_serial_port");
                Sleep(1000);
                continue;
            }

            printf("Device connected to COM%hhu\n", ncomm);
        }

        char scan_buf[SCAN_BUF_SIZE];
        if (!read_scanner(hcomm, event_mask, scan_buf, sizeof(scan_buf)))
        {
            print_err("read_scanner (COM%hhu)", ncomm);
            close_com(hcomm);
            continue;
        }

        printf("Code has been read from device (COM%hhu): %s\n", ncomm, scan_buf);

        pthread_mutex_lock(&log_mutex);

        FILE *timbra_log;
        if (fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "a+"))
            throw_err("fopen_s");

        char date_str[26];
        timestamp(date_str);
        fprintf_s(timbra_log, TIMBRA_LOG_ROW_FMT, scan_buf, postazione_id, date_str);
        fclose(timbra_log);

        pthread_mutex_unlock(&log_mutex);

        pthread_mutex_lock(&send_req_mutex);
        pthread_cond_signal(&send_req_cond);
        pthread_mutex_unlock(&send_req_mutex);
    }

    close_com(hcomm);
}

void *send_timbra_reqs(void *vargp)
{
    const char *hostname = ((ThreadParams *)vargp)->hostname;
    const uint16_t port = ((ThreadParams *)vargp)->port;
    const char *password = ((ThreadParams *)vargp)->password;
    const char *user_agent = ((ThreadParams *)vargp)->user_agent;

    DWORD uname_size = 65;
    char username[uname_size];
    if (!GetUserName(username, &uname_size))
        throw_err("GetComputerName");

    char cookies[1024];
    BOOL has_cookies = get_cookies(cookies, sizeof(cookies));
    if (has_cookies)
        puts("Cookies acquired");
    else
        puts("No cookies available");

    SSL_library_init();

    SSL_CTX *ctx = init_CTX();
    if (ctx == NULL)
        throw_err("init_CTX");

    SOCKET sock = INVALID_SOCKET;
    SSL *ssl = NULL;
    BOOL connected = FALSE;

    while (TRUE)
    {
        if (!connected)
        {
            sock = conn_to_server(hostname, port);

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sock);
            if (SSL_connect(ssl) < 0)
            {
                ERR_print_errors_fp(stderr);
                print_err("SSL_connect");
                Sleep(1000);
                continue;
            }

            puts("----------------------------------------------------------------------------------------------------------");
            show_certs(ssl);
            puts("----------------------------------------------------------------------------------------------------------");

            connected = TRUE;
        }

        char req_buf[SO_MAX_MSG_SIZE], res_buf[SO_MAX_MSG_SIZE], msg_body[SO_MAX_MSG_SIZE];
        int nbytes;

        if (!has_cookies)
        {
            _snprintf_s(msg_body, sizeof(msg_body), sizeof(msg_body) - 1, LOGIN_BODY_FMT, username, password);
            _snprintf_s(req_buf, sizeof(req_buf), sizeof(req_buf) - 1, LOGIN_MSG_FMT, hostname, user_agent, strlen(msg_body), msg_body);

            puts("----------------------------------------------------------------------------------------------------------");
            puts("Login Request");
            puts(req_buf);
            puts("----------------------------------------------------------------------------------------------------------");

            if (SSL_write(ssl, req_buf, strlen(req_buf)) <= 0)
            {
                ERR_print_errors_fp(stderr);
                print_err("Unable to send login request.");
                connected = FALSE;
                continue;
            }

            if ((nbytes = SSL_read(ssl, res_buf, sizeof(res_buf))) <= 0)
            {
                ERR_print_errors_fp(stderr);
                print_err("No response. (nbytes=%d)", nbytes);
                connected = FALSE;
                continue;
            }
            res_buf[nbytes] = '\0';

            puts("----------------------------------------------------------------------------------------------------------");
            puts("Login Response");
            puts(res_buf);
            puts("----------------------------------------------------------------------------------------------------------");

            has_cookies = save_cookies(res_buf, sizeof(res_buf), cookies, sizeof(cookies));
            if (!has_cookies)
            {
                print_err("save_cookies");
                Sleep(4 * 1000);
                continue;
            }

            puts("Cookies acquired");
        }

        pthread_mutex_lock(&send_req_mutex);
        pthread_cond_wait(&send_req_cond, &send_req_mutex);

        pthread_mutex_lock(&log_mutex);

        if (!read_timbra_log(msg_body, sizeof(msg_body)))
        {
            print_err("read_timbra_log");
            pthread_mutex_unlock(&log_mutex);
            pthread_mutex_unlock(&send_req_mutex);
            continue;
        }
        size_t body_len = strlen(msg_body);

        _snprintf_s(req_buf, sizeof(req_buf), sizeof(req_buf) - 1, TIMBRA_MSG_FMT, hostname, user_agent, cookies, body_len, msg_body);

        puts("----------------------------------------------------------------------------------------------------------");
        puts("Timbra Request");
        puts(req_buf);
        puts("----------------------------------------------------------------------------------------------------------");

        // send request
        if (SSL_write(ssl, req_buf, strlen(req_buf)) <= 0)
        {
            ERR_print_errors_fp(stderr);
            print_err("Unable to send request.");
            pthread_mutex_unlock(&log_mutex);
            pthread_mutex_unlock(&send_req_mutex);
            connected = FALSE;
            continue;
        }

        // recive response
        if ((nbytes = SSL_read(ssl, res_buf, sizeof(res_buf))) <= 0)
        {
            ERR_print_errors_fp(stderr);
            print_err("No response. (nbytes=%d)", nbytes);
            pthread_mutex_unlock(&log_mutex);
            pthread_mutex_unlock(&send_req_mutex);
            connected = FALSE;
            continue;
        }
        res_buf[nbytes] = '\0';

        puts("----------------------------------------------------------------------------------------------------------");
        puts("Timbra Response");
        puts(req_buf);
        puts("----------------------------------------------------------------------------------------------------------");

        uint16_t status_code = get_response_status(res_buf);
        switch (status_code)
        {
        case UNAUTHORIZED_STATUS_CODE:
        case FORBIDDEN_STATUS_CODE:
            has_cookies = FALSE;
            print_err("Timbra requests have been rejected. Status code: %hu", status_code);
            break;
        case SUCCESS_STATUS_CODE:
            printf("Timbra requests have been (fully/partialy) accepted.\n");
            empty_timbra_log();
            break;
        case CLIENT_ERROR_STATUS_CODE:
            printf("Timbra requests have been rejected (deleting log file). Status code: %hu\n", status_code);
            empty_timbra_log();
            break;
        default:
            print_err("Timbra requests have been rejected. Status code: %hu", status_code);
        }

        pthread_mutex_unlock(&log_mutex);
        pthread_mutex_unlock(&send_req_mutex);
    }

    return NULL;
}

uint8_t find_serial_port(HANDLE *hcomm)
{
    char comm_name[16];

    for (uint8_t i = NMIN_COM; i && i <= NMAX_COM; ++i)
    {
        _snprintf_s(comm_name, sizeof(comm_name), sizeof(comm_name) - 1, COM_PORT_FORMAT, i);

        *hcomm = CreateFile(
            comm_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (*hcomm != INVALID_HANDLE_VALUE)
            return i;

        close_com(hcomm);
    }

    return INVALID_COM_NUM;
}

uint8_t open_serial_port(HANDLE *hcomm, DWORD *event_mask)
{
    uint8_t comm_num = find_serial_port(hcomm);
    if (!comm_num)
    {
        close_com(hcomm);
        print_err("find_serial_port");
        return INVALID_COM_NUM;
    }

    if (!FlushFileBuffers(*hcomm))
    {
        close_com(hcomm);
        print_err("FlushFileBuffers");
        return INVALID_COM_NUM;
    }

    DCB dcb_serial_params = {0};
    dcb_serial_params.DCBlength = sizeof(dcb_serial_params);

    if (!GetCommState(*hcomm, &dcb_serial_params))
    {
        close_com(hcomm);
        print_err("GetCommState");
        return INVALID_COM_NUM;
    }

    dcb_serial_params.BaudRate = CBR_9600;
    dcb_serial_params.ByteSize = 8;
    dcb_serial_params.StopBits = ONESTOPBIT;
    dcb_serial_params.Parity = NOPARITY;

    if (!SetCommState(*hcomm, &dcb_serial_params))
    {
        close_com(hcomm);
        print_err("SetCommState");
        return INVALID_COM_NUM;
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;

    if (!SetCommTimeouts(*hcomm, &timeouts))
    {
        close_com(hcomm);
        print_err("SetCommTimeouts");
        return INVALID_COM_NUM;
    }

    *event_mask = (DWORD)EV_RXCHAR;
    if (!SetCommMask(*hcomm, *event_mask))
    {
        close_com(hcomm);
        print_err("SetCommMask");
        return INVALID_COM_NUM;
    }

    return comm_num;
}

void close_com(HANDLE *hcomm)
{
    if (*hcomm)
        CloseHandle(*hcomm);
    *hcomm = INVALID_HANDLE_VALUE;
}

BOOL read_scanner(HANDLE hcomm, DWORD event_mask, char *buf, size_t size)
{

    if (!WaitCommEvent(hcomm, &event_mask, NULL))
    {
        print_err("WaitCommEvent");
        close_com(&hcomm);
        return FALSE;
    }

    char tmp_ch;
    DWORD bytes_read;
    size_t i = 0;
    do
    {
        tmp_ch = 0;

        if (!ReadFile(hcomm, &tmp_ch, sizeof(tmp_ch), &bytes_read, NULL))
        {
            print_err("ReadFile");
            close_com(&hcomm);
            return FALSE;
        }

        buf[i++] = tmp_ch;
    } while (bytes_read && i < size && buf[i - 1] != '\n' && buf[i - 1] != '\r');

    buf[i - 1] = 0;

    return TRUE;
}

void timestamp(char *buf)
{
    const struct tm tm = *localtime(&(time_t){time(NULL)});
    if (asctime_s(buf, 26, &tm))
        throw_err("asctime_s");
    buf[24] = 0;
}

SSL_CTX *init_CTX(void)
{
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings();     /* Bring in and register error messages */

    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);             /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        print_err("SSL_CTX_new");
        return NULL;
    }

    return ctx;
}

void show_certs(SSL *ssl)
{
    char *line;

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        puts("Info: No client certificates configured.");
        return;
    }

    puts("Server certificates:");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
}

SOCKET conn_to_server(const char *hostname, const uint16_t port)
{
    SOCKET sock;
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
    {
        print_err("WSAStartup. Failed. Error Code : %d.", WSAGetLastError());
        return INVALID_SOCKET;
    }

    // Create a socket
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        print_err("Could not create socket : %d.", WSAGetLastError());
        WSACleanup();
        return INVALID_SOCKET;
    }

    // set socket options
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(hostname);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    printf("Attempt connection to %s:%d.\n", hostname, port);

    // loop while connection is not enstablished
    BOOL connected = FALSE;
    uint8_t ntries = 1;
    while (!connected && ntries < NMAX_CONN_TRIES)
    {
        // connect to server
        // if connection failed retry to connect after 1 sec
        connected = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR;
        if (!connected)
        {
            ++ntries;
            print_err("Connection to server failed. Error %d", WSAGetLastError());
            Sleep(1000);
        }
    }

    if (!connected)
    {
        WSACleanup();
        print_err("Failed to enstablish connection to %s:%d.\n", hostname, port);
        return INVALID_SOCKET;
    }

    printf("Connection to %s:%d enstablished (%hhu tries).\n", hostname, port, ntries);
    return sock;
}

BOOL get_cookies(char *buf, size_t size)
{
    FILE *cookie_jar;
    if (fopen_s(&cookie_jar, COOKIES_FILENAME, "r"))
    {
        print_err("fopen_s");
        return FALSE;
    }

    if (!fgets(buf, size, cookie_jar))
    {
        print_err("fgets");
        return FALSE;
    }

    fclose(cookie_jar);

    return TRUE;
}

BOOL save_cookies(char *src, size_t src_size, char *dest, size_t dest_size)
{
    char *str_ptr = strstr(src, "Set-Cookie: ");
    if (!str_ptr)
    {
        print_err("strstr");
        return FALSE;
    }

    str_ptr = strtok(str_ptr, " ");
    str_ptr = strtok(NULL, "\r\n");
    if (!str_ptr)
    {
        print_err("str_tok");
        return FALSE;
    }

    if (strcpy_s(dest, dest_size, str_ptr))
        throw_err("strcpy_s");

    FILE *cookie_jar;
    if (fopen_s(&cookie_jar, COOKIES_FILENAME, "w"))
        throw_err("fopen_s");

    if (fputs(str_ptr, cookie_jar) == EOF)
        throw_err("fputs");

    fclose(cookie_jar);

    return TRUE;
}

BOOL read_timbra_log(char *buf, size_t size)
{
    FILE *timbra_log;

    if (fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "r"))
    {
        print_err("fopen_s");
        return FALSE;
    }

    size_t i = 1;

    while (i < size && !feof(timbra_log))
        buf[i++] = fgetc(timbra_log);

    buf[0] = '[';
    buf[i - 2] = ']';
    buf[i - 1] = '\0';

    fclose(timbra_log);

    return TRUE;
}

BOOL empty_timbra_log(void)
{
    FILE *timbra_log;
    errno_t ret = fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "w");

    if (ret)
    {
        print_err("fopen_s");
    }
    else
    {
        fclose(timbra_log);
    }

    return !ret;
}

uint16_t get_response_status(char *res)
{
    uint16_t status_code = 0;

    char *str_ptr = strstr(res, "HTTP/1.1");
    if (!str_ptr)
    {
        print_err("strstr");
        return status_code;
    }

    str_ptr = strtok(str_ptr, " ");
    str_ptr = strtok(NULL, " ");
    if (!str_ptr)
    {
        print_err("strtok");
        return status_code;
    }

    sscanf_s(str_ptr, "%hu", &status_code);
    return status_code;
}