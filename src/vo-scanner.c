/* vo-scanner.c */

#include "vo-scanner.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t send_req_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_req_cond = PTHREAD_COND_INITIALIZER;

PopupInfo popup_info = {0};

int main(int argc, char *argv[])
{
    if (argc < 3)
        throw_err("usage: %s <password> <postazioneId> <hostname> <port> <username>", argv[0]);

    char hostname[NI_MAXHOST];
    if (!resolve_domain(argc > 3 ? argv[3] : DEFAULT_HOSTNAME, hostname, sizeof(hostname)))
        throw_err("resolve_domain");

    DWORD UNAME_MAX_LEN = 65;
    char username[UNAME_MAX_LEN];
    if (argc > 5)
    {
        size_t uname_len = strlen(argv[5]);
        strncpy(username, argv[5], uname_len < UNAME_MAX_LEN ? uname_len : UNAME_MAX_LEN);
    }
    else if (!GetUserName(username, &UNAME_MAX_LEN))
        throw_err("GetComputerName");

    ReqsThreadParams reqs_params = {
        .port = argc > 4 ? (uint16_t)atoi(argv[4]) : DEFAULT_HTTPS_SERVER_PORT,
        .hostname = hostname,
        .username = username,
        .password = argv[1],
        .user_agent = argv[0]};
    LogThreadParams log_params = {
        .postazione_id = (uint32_t)atoi(argv[2])};

    CreateDirectory("data", NULL);

    pthread_t reqs_pid;
    if (pthread_create(&reqs_pid, NULL, send_timbra_reqs, (void *)&reqs_params))
        throw_err("pthread_create reqs");
    pthread_t logger_pid;
    if (pthread_create(&logger_pid, NULL, timbra_logger, (void *)&log_params))
        throw_err("pthread_create logger");

    popup_manager();

    puts("Waiting for children.");
    pthread_join(reqs_pid, NULL);
    pthread_join(logger_pid, NULL);

    puts("Execution terminated.");

    return EXIT_SUCCESS;
}

void *timbra_logger(void *tparams)
{
    const uint32_t postazione_id = ((LogThreadParams *)tparams)->postazione_id;

    HANDLE hcomm = INVALID_HANDLE_VALUE;
    DWORD event_mask;
    uint8_t ncomm = INVALID_COM_NUM;

    while (true)
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

        char scan_buf[256];
        if (!read_scanner(hcomm, event_mask, scan_buf, sizeof(scan_buf)))
        {
            print_err("read_scanner (COM%hhu)", ncomm);
            close_com(hcomm);
            continue;
        }

        printf("Code has been read from device (COM%hhu): %s\n", ncomm, scan_buf);

        ScanData scan_data = {0};
        if (!parse_scan_data(scan_buf, &scan_data))
        {
            print_err("Badge Code %s has been rejected. Invalid Code.", scan_buf);

            if (strlen(scan_buf))
            {
                strcpy(popup_info.inner_text, "Impossibile Timbrare Badge\n\nCodice Non Valido");
                popup_info.bg_color = RGB(255, 0, 0);
                SendMessage(popup_info.hwnd, WM_USER, 0, 0);
            }

            continue;
        }

        pthread_mutex_lock(&log_mutex);

        FILE *timbra_log;
        if (fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "a+"))
            throw_err("fopen_s");

        char date_str[26];
        timestamp(date_str);
        fprintf_s(timbra_log, TIMBRA_LOG_ROW_FMT, scan_data.code, postazione_id, date_str);
        fclose(timbra_log);

        PlaySound(NULL, 0, 0);
        PlaySound(scan_data.mark_in ? BEEP_IN : BEEP_OUT, NULL, SND_FILENAME | SND_ASYNC);

        char popup_msg[128];
        sprintf(popup_info.inner_text, "Badge Timbrato con Successo\n\n%s %s %s Struttura",
                scan_data.name, scan_data.surname, scan_data.mark_in ? "Entra In" : "Esce Da");
        strncpy(popup_info.inner_text, popup_msg, min(strlen(popup_msg), sizeof(popup_info.inner_text) - 1));
        popup_info.bg_color = RGB(0, 255, 0);
        SendMessage(popup_info.hwnd, WM_USER, 0, 0);

        pthread_mutex_unlock(&log_mutex);

        pthread_mutex_lock(&send_req_mutex);
        pthread_cond_signal(&send_req_cond);
        pthread_mutex_unlock(&send_req_mutex);
    }

    close_com(hcomm);

    return NULL;
}

void *send_timbra_reqs(void *vargp)
{
    const uint16_t port = ((ReqsThreadParams *)vargp)->port;
    const char *hostname = ((ReqsThreadParams *)vargp)->hostname;
    const char *username = ((ReqsThreadParams *)vargp)->username;
    const char *password = ((ReqsThreadParams *)vargp)->password;
    const char *user_agent = ((ReqsThreadParams *)vargp)->user_agent;

    char cookies[1024];
    bool has_cookies = get_cookies(cookies, sizeof(cookies));
    puts(has_cookies ? "Cookies acquired" : "No cookies available");

    SSL_library_init();

    SSL_CTX *ctx = init_CTX();
    if (ctx == NULL)
        throw_err("init_CTX");

    SOCKET sock = INVALID_SOCKET;
    SSL *ssl = NULL;
    bool connected = false;

    while (true)
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

            connected = true;
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
                connected = false;
                continue;
            }

            if ((nbytes = SSL_read(ssl, res_buf, sizeof(res_buf))) <= 0)
            {
                ERR_print_errors_fp(stderr);
                print_err("No response. (nbytes=%d)", nbytes);
                connected = false;
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
                Sleep(4000);
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
            connected = false;
            continue;
        }

        // recive response
        if ((nbytes = SSL_read(ssl, res_buf, sizeof(res_buf))) <= 0)
        {
            ERR_print_errors_fp(stderr);
            print_err("No response. (nbytes=%d)", nbytes);
            pthread_mutex_unlock(&log_mutex);
            pthread_mutex_unlock(&send_req_mutex);
            connected = false;
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
            has_cookies = false;
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

void popup_manager()
{
    static const char CLASS_NAME[] = "popup";

    WNDCLASS wc;
    memset(&wc, 0, sizeof(WNDCLASS));
    wc.lpfnWndProc = window_proc;
    wc.hInstance = NULL;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClass(&wc);

    strcpy(popup_info.inner_text, "");
    popup_info.bg_color = RGB(0, 0, 0);
    popup_info.font = CreateFont(40, 0, 0, 0, FW_DONTCARE, false, false, false, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                                 CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, NULL);
    popup_info.hwnd = CreateWindow(
        CLASS_NAME,
        "VeroOpen",
        WS_OVERLAPPED | WS_CAPTION | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 150,
        NULL,
        NULL,
        NULL,
        NULL);
    if (popup_info.hwnd == NULL)
        throw_err("CreateWindow");

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK window_proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    PAINTSTRUCT ps;
    RECT rect;
    HDC hdc;
    HFONT font;

    switch (uMsg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_PAINT:
    {
        const size_t txt_len = strlen(popup_info.inner_text);

        hdc = BeginPaint(hwnd, &ps);

        SelectObject(hdc, popup_info.font);

        GetClientRect(hwnd, &rect);
        FillRect(hdc, &rect, CreateSolidBrush(popup_info.bg_color));

        SetBkColor(hdc, popup_info.bg_color);
        DrawText(hdc, popup_info.inner_text, txt_len, &rect, DT_CENTER | DT_VCENTER);

        EndPaint(hwnd, &ps);
    }
        return 0;

    case WM_CLOSE:
    case WM_TIMER:
        ShowWindow(hwnd, SW_HIDE);
        KillTimer(hwnd, TIMER_ID);
        return 0;

    case WM_USER:
        KillTimer(hwnd, TIMER_ID);
        InvalidateRect(hwnd, NULL, true);
        ShowWindow(hwnd, SW_NORMAL);
        PlaySound((LPCTSTR)SND_ALIAS_SYSTEMSTART, NULL, SND_ALIAS_ID);
        SetTimer(hwnd, TIMER_ID, 5000, NULL);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
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

bool read_scanner(HANDLE hcomm, DWORD event_mask, char *buf, size_t size)
{

    if (!WaitCommEvent(hcomm, &event_mask, NULL))
    {
        print_err("WaitCommEvent");
        close_com(&hcomm);
        return false;
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
            return false;
        }

        if (tmp_ch >= 33 && tmp_ch <= 126)
            buf[i++] = tmp_ch;
    } while (bytes_read && i < size && buf[i] != '\n' && buf[i] != '\r');

    buf[i] = 0;

    return true;
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

bool resolve_domain(const char *hostname, char *ipv4_str, size_t ipv4_str_size)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
    {
        print_err("WSAStartup. Error Code : %d.", WSAGetLastError());
        return false;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result;
    if (GetAddrInfo(hostname, NULL, &hints, &result))
    {
        print_err("GetAddrInfo. Error Code: %d", WSAGetLastError());
        WSACleanup();
        return false;
    };

    for (struct addrinfo *res_ptr = result; res_ptr; res_ptr = res_ptr->ai_next)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res_ptr->ai_addr;
        void *addr = &(ipv4->sin_addr);
        if (inet_ntop(AF_INET, addr, ipv4_str, ipv4_str_size))
        {
            printf("Successfully resolved IPv4 address %s from domain name %s\n", ipv4_str, hostname);
            freeaddrinfo(result);
            WSACleanup();
            return true;
        };
    }

    print_err("Failed to resolve an IPv4 address from domain name %s", hostname);
    freeaddrinfo(result);
    WSACleanup();
    return false;
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
    bool connected = false;
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

bool get_cookies(char *buf, size_t size)
{
    FILE *cookie_jar;
    if (fopen_s(&cookie_jar, COOKIES_FILENAME, "r"))
    {
        print_err("fopen_s");
        return false;
    }

    if (!fgets(buf, size, cookie_jar))
    {
        print_err("fgets");
        return false;
    }

    fclose(cookie_jar);

    return true;
}

bool save_cookies(char *src, size_t src_size, char *dest, size_t dest_size)
{
    char *str_ptr = strstr(src, "Set-Cookie: ");
    if (!str_ptr)
    {
        print_err("strstr");
        return false;
    }

    str_ptr = strtok(str_ptr, " ");
    str_ptr = strtok(NULL, "\r\n");
    if (!str_ptr)
    {
        print_err("str_tok");
        return false;
    }

    if (strcpy_s(dest, dest_size, str_ptr))
        throw_err("strcpy_s");

    FILE *cookie_jar;
    if (fopen_s(&cookie_jar, COOKIES_FILENAME, "w"))
        throw_err("fopen_s");

    if (fputs(str_ptr, cookie_jar) == EOF)
        throw_err("fputs");

    fclose(cookie_jar);

    return true;
}

bool read_timbra_log(char *buf, size_t size)
{
    FILE *timbra_log;

    if (fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "r"))
    {
        print_err("fopen_s");
        return false;
    }

    size_t i = 1;

    while (i < size && !feof(timbra_log))
        buf[i++] = fgetc(timbra_log);

    buf[0] = '[';
    buf[i - 2] = ']';
    buf[i - 1] = '\0';

    fclose(timbra_log);

    return true;
}

bool empty_timbra_log(void)
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

bool parse_scan_data(char *buf, ScanData *out)
{
    static const char delim[] = "~";

    char *str_token = strtok(buf, delim);
    if (!str_token)
        return false;

    const uint8_t code_len = min(strlen(str_token), sizeof(out->code) - 1);
    if (!is_badge_code_valid(buf, code_len))
        return false;

    strncpy(out->code, str_token, code_len);
    out->code_len = code_len;
    out->mark_in = out->code[0] == '0';

    str_token = strtok(NULL, delim);
    if (str_token)
        strncpy(out->name, str_token, min(strlen(str_token), sizeof(out->name) - 1));

    str_token = strtok(NULL, delim);
    if (str_token)
        strncpy(out->surname, str_token, min(strlen(str_token), sizeof(out->surname) - 1));

    return true;
}

bool is_badge_code_valid(const char *code_str, const size_t code_str_size)
{
    static const uint8_t CODE_LEN = 10;
    static const char VALID_PREFIXIES[][2] = {"01", "11"};
    static const uint8_t VALID_PREF_SIZE = sizeof(VALID_PREFIXIES) / sizeof(VALID_PREFIXIES[0]);

    if (strlen(code_str) != CODE_LEN)
        return false;

    bool has_valid_pref = false;
    for (uint8_t i = 0; i < VALID_PREF_SIZE; ++i)
    {
        if (!strncmp(code_str, VALID_PREFIXIES[i], sizeof(VALID_PREFIXIES[i])))
        {
            has_valid_pref = true;
            break;
        }
    }
    if (!has_valid_pref)
        return false;

    for (uint8_t i = 1; i < CODE_LEN; ++i)
    {
        if (code_str[i] < '0' || code_str[i] > '9')
            return false;
    }

    return true;
}