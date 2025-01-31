/* vo-scanner.c */

#include "vo_scanner.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_req_cond = PTHREAD_COND_INITIALIZER;

bool send_req = false;
PopupInfo popup_info = {0};

int main(int argc, char **argv)
{
    puts("Program execution started.");

    ProgramArgs args;
    parse_args(argc, argv, &args);

    CreateDirectory("data", NULL);

    pthread_t reqs_pid;
    if (pthread_create(&reqs_pid, NULL, send_timbra_reqs, (void *)&args.reqs))
        throw_err("Couldn't create reqs routine thread");
    pthread_t logger_pid;
    if (pthread_create(&logger_pid, NULL, logger_routine, (void *)&args.log))
        throw_err("Couldn't create logger routine thread");
    popup_manager();

    puts("Main thread waiting for child processes.");
    pthread_join(reqs_pid, NULL);
    pthread_join(logger_pid, NULL);

    puts("Program execution terminated.");

    return EXIT_SUCCESS;
}

void parse_args(int argc, char **argv, ProgramArgs *args)
{
    if (argc < 3)
        throw_err("usage: %s <password> <postazioneId> <hostname> <port> <username>", argv[0]);

    args->reqs.port = argc > 4 ? argv[4] : DEFAULT_HTTPS_SERVER_PORT;
    args->reqs.hostname = argc > 3 ? argv[3] : DEFAULT_HOSTNAME;
    args->reqs.username = argc > 5 ? argv[5] : NULL;
    args->reqs.password = argv[1];

    args->log.postazione_id = (uint32_t)atoi(argv[2]);
}

void *logger_routine(void *args)
{
    const uint32_t postazione_id = ((LogArgs *)args)->postazione_id;

    HANDLE hcom = INVALID_HANDLE_VALUE;
    DWORD event_mask;
    uint8_t ncom = INVALID_COM_NUM;

    while (true)
    {
        if (hcom == INVALID_HANDLE_VALUE)
        {
            if (!(ncom = open_serial_port(&hcom, &event_mask)))
            {
                print_err("Couldn't open serial device");
                Sleep(1000);
                continue;
            }

            printf("[LOG] Device connected to COM%hhu\n", ncom);
        }

        char scan_buf[256];
        if (!read_scanner(hcom, event_mask, scan_buf, sizeof(scan_buf)))
        {
            print_err("Error reading from device (COM%hhu)", ncom);
            close_com(hcom);
            continue;
        }

        printf("[LOG] Scan data read from device (COM%hhu): %s\n", ncom, scan_buf);

        ScanData scan_data = {0};
        if (!parse_scan_data(scan_buf, &scan_data))
        {
            print_err("Invalid scan data %s", scan_buf);

            if (strlen(scan_buf))
            {
                strncpy(popup_info.inner_text, POPUP_MSG_FAIL, lengthof(POPUP_MSG_FAIL));
                popup_info.bg_color = RGB(255, 0, 0);
                SendMessage(popup_info.hwnd, WM_USER, 0, 0);
            }
        }
        else
        {
            write_to_timbra_log(scan_data.code, postazione_id);

            PlaySound(scan_data.mark_in ? BEEP_IN : BEEP_OUT, NULL, SND_FILENAME | SND_ASYNC);

            char msg_suffix[10];
            strncpy(msg_suffix, scan_data.mark_in ? "Entra In" : "Esce Da", lengthof(msg_suffix));
            size_t popup_msg_len = lengthof(POPUP_MSG_SUCC_FMT) + strlen(scan_data.name) +
                                   strlen(scan_data.surname) + strlen(msg_suffix);
            snprintf(popup_info.inner_text, popup_msg_len, POPUP_MSG_SUCC_FMT,
                     scan_data.name, scan_data.surname, msg_suffix);
            popup_info.bg_color = scan_data.mark_in ? RGB(0, 255, 0) : RGB(255, 0, 0);
            SendMessage(popup_info.hwnd, WM_USER, 0, 0);
        }
    }

    close_com(hcom);

    return NULL;
}

void *send_timbra_reqs(void *args)
{
    char *tmp_uname = ((ReqsArgs *)args)->username;
    DWORD UNAME_MAX_LEN = 65;
    char uname[UNAME_MAX_LEN];
    if (!tmp_uname)
    {
        bool got_uname;
#ifndef _DEBUG_UNAME
        got_uname = GetUserName(uname, &UNAME_MAX_LEN);
#else
        got_uname = GetComputerName(uname, &UNAME_MAX_LEN);
#endif
        if (!got_uname)
            throw_err("Couldn't get username");
        tmp_uname = uname;
    }

    const char *port = ((ReqsArgs *)args)->port;
    const char *hostname = ((ReqsArgs *)args)->hostname;
    const char *username = tmp_uname;
    const char *password = ((ReqsArgs *)args)->password;

    char cookies[1024];
    bool has_cookies = get_cookies(cookies, sizeof(cookies));
    puts(has_cookies ? "[REQ] Cookies acquired" : "[REQ] No cookies available");

    while (true)
    {
        SSL *ssl = init_https_conn(hostname, port);
        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            print_err("Couldn't connect to remote https server %s:%s", hostname, port);
            Sleep(1000);
            continue;
        }

        printf("[REQ] Connection with remote server %s:%s enstablished\n", hostname, port);

        puts("----------------------------------------------------------------------------------------------------------");
        show_certs(ssl);
        puts("----------------------------------------------------------------------------------------------------------");

        if (!has_cookies)
        {
            if (!send_login_req(ssl, username, password, hostname, cookies, sizeof(cookies)))
            {
                ERR_print_errors_fp(stderr);
                print_err("Couldn't send login request");
                has_cookies = false;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                Sleep(1000);
            }
            else
            {
                puts("[REQ] Cookies acquired by login request");
                has_cookies = true;
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            continue;
        }

        pthread_mutex_lock(&log_mutex);
        if (!send_req)
            pthread_cond_wait(&send_req_cond, &log_mutex);

        uint16_t status_code = 0;
        if (!send_mark_req(ssl, hostname, cookies, &status_code))
        {
            print_err("Couldn't send mark request");
            status_code = 0;
        }

        switch (status_code)
        {
        case UNAUTHORIZED_STATUS_CODE:
        case FORBIDDEN_STATUS_CODE:
            has_cookies = false;
            print_err("Timbra requests have been rejected. Status code: %hu", status_code);
            break;
        case SUCCESS_STATUS_CODE:
            printf("[REQ] Timbra requests have been (fully/partialy) accepted.\n");
            if (!empty_timbra_log())
                print_err("Coulnd't empty timbra log file");
            else
                puts("[REQ] Timbra log file has been blanked");
            break;
        case CLIENT_ERROR_STATUS_CODE:
            printf("[REQ] Timbra requests have been rejected (deleting log file). Status code: %hu\n", status_code);
            if (!empty_timbra_log())
                print_err("Coulnd't empty timbra log file");
            else
                puts("[REQ] Timbra log file has been blanked");
            break;
        default:
            print_err("Timbra requests have been rejected. Status code: %hu", status_code);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);

        send_req = false;
        pthread_mutex_unlock(&log_mutex);
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
    popup_info.font = CreateFont(40, 0, 0, 0, FW_BOLD, false, false, false, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                                 CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, NULL);
    if (popup_info.font == NULL)
        throw_err("CreateFont");
    popup_info.hwnd = CreateWindow(
        CLASS_NAME,
        "VeroOpen",
        WS_OVERLAPPED | WS_CAPTION | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, WIN_WIDTH, WIN_HEIGHT,
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
    // HFONT font;
    DEVMODEA monitor;

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

        if (EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &monitor))
        {
            const uint16_t wposx = (monitor.dmPelsWidth - WIN_WIDTH) / 2;
            const uint16_t wposy = (monitor.dmPelsHeight - WIN_HEIGHT) / 8;
            MoveWindow(hwnd, wposx, wposy, WIN_WIDTH, WIN_HEIGHT, false);
        }
        else
        {
            print_err("EnumDisplaySettings");
        }

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
        SetTimer(hwnd, TIMER_ID, 5000, NULL);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

uint8_t find_serial_port(HANDLE *hcom)
{
    char com_name[16];

    for (uint8_t i = NMIN_COM; i; ++i)
    {
        snprintf(com_name, sizeof(com_name), COM_PORT_FORMAT, i);

        *hcom = CreateFile(
            com_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            // FILE_ATTRIBUTE_NORMAL,
            0,
            NULL);

        if (*hcom != INVALID_HANDLE_VALUE)
            return i;

        close_com(hcom);
    }

    return INVALID_COM_NUM;
}

uint8_t open_serial_port(HANDLE *hcom, DWORD *event_mask)
{
    uint8_t ncom = find_serial_port(hcom);
    if (!ncom)
    {
        close_com(hcom);
        print_err("Couldn't find any available serial port");
        return INVALID_COM_NUM;
    }

    if (!FlushFileBuffers(*hcom))
    {
        close_com(hcom);
        print_err("FlushFileBuffers");
        return INVALID_COM_NUM;
    }

    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);

    if (!GetCommState(*hcom, &dcb))
    {
        close_com(hcom);
        print_err("Couldn't get serial device attributes");
        return INVALID_COM_NUM;
    }

    dcb.BaudRate = CBR_9600;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity = NOPARITY;

    if (!SetCommState(*hcom, &dcb))
    {
        close_com(hcom);
        print_err("Couldn't set serial device attributes");
        return INVALID_COM_NUM;
    }

    COMMTIMEOUTS timeouts = {0};

    if (!GetCommTimeouts(*hcom, &timeouts))
    {
        close_com(hcom);
        print_err("Couldn't get serial device timeout attributes");
        return INVALID_COM_NUM;
    }

    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;

    if (!SetCommTimeouts(*hcom, &timeouts))
    {
        close_com(hcom);
        print_err("Couldn't set serial device timeout attributes");
        return INVALID_COM_NUM;
    }

    *event_mask = (DWORD)EV_RXCHAR;
    if (!SetCommMask(*hcom, *event_mask))
    {
        close_com(hcom);
        print_err("Couldn't set serial device event mask");
        return INVALID_COM_NUM;
    }

    return ncom;
}

void close_com(HANDLE *hcom)
{
    if (*hcom && *hcom != INVALID_HANDLE_VALUE)
        CloseHandle(*hcom);
    *hcom = INVALID_HANDLE_VALUE;
}

bool read_scanner(HANDLE hcom, DWORD event_mask, char *buf, size_t size)
{

    if (!WaitCommEvent(hcom, &event_mask, NULL))
    {
        print_err("WaitCommEvent");
        close_com(&hcom);
        return false;
    }

    char tmp_ch;
    DWORD bytes_read;
    size_t i = 0;
    do
    {
        tmp_ch = 0;

        if (!ReadFile(hcom, &tmp_ch, 1, &bytes_read, NULL))
        {
            print_err("Error reading from serial device");
            close_com(&hcom);
            return false;
        }

        if (tmp_ch >= 33 && tmp_ch <= 126)
            buf[i++] = tmp_ch;
    } while (bytes_read && i < size && buf[i] != '\n' && buf[i] != '\r');

    buf[i] = 0;

    return true;
}

void write_to_timbra_log(const char *code, const uint32_t postazione_id)
{
    pthread_mutex_lock(&log_mutex);
    FILE *timbra_log = fopen(TIMBRA_LOG_FILENAME, "a+");
    if (!timbra_log)
        throw_err("Couldn't open " TIMBRA_LOG_FILENAME " file");

    char str_date[32];
    timestamp(str_date);
    fprintf(timbra_log, TIMBRA_LOG_ROW_FMT, code, postazione_id, str_date);
    fclose(timbra_log);

    send_req = true;
    pthread_cond_signal(&send_req_cond);
    pthread_mutex_unlock(&log_mutex);
}

void timestamp(char *buf)
{
    const struct tm tm = *localtime(&(time_t){time(NULL)});
    if (asctime_s(buf, 26, &tm))
        throw_err("asctime_s");
    buf[24] = 0;
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

SSL *init_https_conn(const char *hostname, const char *port)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        print_err("Couldn't create SSL context");
        return NULL;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, port, &hints, &res))
    {
        ERR_print_errors_fp(stderr);
        print_err("Couldn't resolve address of %s:%s", hostname, port);
        SSL_CTX_free(ctx);
        return NULL;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
    {
        print_err("WSAStartup. Failed. Error Code : %d.", WSAGetLastError());
        return NULL;
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock != INVALID_SOCKET)
    {
        print_err("Couldn't create socket : %d.", WSAGetLastError());
        WSACleanup();
        ERR_print_errors_fp(stderr);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
    {
        print_err("Connection to server failed. Error %d", WSAGetLastError());
        WSACleanup();
        ERR_print_errors_fp(stderr);
        print_err("Couldn't connect to server");
        closesocket(sock);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return NULL;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        WSACleanup();
        ERR_print_errors_fp(stderr);
        print_err("Couldn't create SSL object");
        closesocket(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0)
    {
        WSACleanup();
        ERR_print_errors_fp(stderr);
        print_err("Error during SSL handshaking");
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ssl;
}

bool send_login_req(SSL *ssl, const char *username, const char *password, const char *hostname, char *cookies, size_t cookies_size)
{
    char buf[SO_MAX_MSG_SIZE], msg_body[512];
    snprintf(msg_body, sizeof(msg_body), LOGIN_BODY_FMT, username, password);
    snprintf(buf, sizeof(buf), LOGIN_MSG_FMT, hostname, strlen(msg_body), msg_body);

    puts("----------------------------------------------------------------------------------------------------------");
    puts("Login Request");
    puts(buf);
    puts("----------------------------------------------------------------------------------------------------------");

    if (SSL_write(ssl, buf, strlen(buf)) <= 0)
    {
        ERR_print_errors_fp(stderr);
        print_err("Unable to send login request.");
        return false;
    }

    int nbytes = SSL_read(ssl, buf, lengthof(buf));
    while (nbytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        print_err("No response for login. (nbytes=%d)", nbytes);
        return false;
    }
    buf[nbytes] = 0;

    puts("----------------------------------------------------------------------------------------------------------");
    printf("Received Login Response (nbytes=%d)\n", nbytes);
    puts(buf);
    puts("----------------------------------------------------------------------------------------------------------");

    if (!save_cookies(buf, cookies, cookies_size))
    {
        ERR_print_errors_fp(stderr);
        print_err("Failed to save cookies into file");
        return false;
    }

    return true;

    // int nbytes;
    // while ((nbytes = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0)
    // {
    //     buf[nbytes] = 0;

    //     puts("----------------------------------------------------------------------------------------------------------");
    //     puts("Login Response");
    //     puts(buf);
    //     puts("----------------------------------------------------------------------------------------------------------");

    //     if (save_cookies(buf, sizeof(buf), cookies, cookies_size))
    //     {
    //         return true;
    //     }
    //     else
    //     {
    //         print_err("Failed to save cookies into file");
    //         continue;
    //     }
    // }

    // ERR_print_errors_fp(stderr);
    // print_err("No response for login. (nbytes=%d)", nbytes);
    // return false;
}

bool send_mark_req(SSL *ssl, const char *hostname, const char *cookies, uint16_t *status_code)
{
    char buf[SO_MAX_MSG_SIZE], msg_body[SO_MAX_MSG_SIZE - lengthof(TIMBRA_MSG_FMT) - 10];

    if (!read_timbra_log(msg_body, sizeof(msg_body)))
    {
        print_err("Couldn't read timbra log file");
        return false;
    }
    size_t body_len = strlen(msg_body);
    snprintf(buf, sizeof(buf), TIMBRA_MSG_FMT, hostname, cookies, body_len, msg_body);

    puts("----------------------------------------------------------------------------------------------------------");
    puts("Timbra Request");
    puts(buf);
    puts("----------------------------------------------------------------------------------------------------------");

    if (SSL_write(ssl, buf, strlen(buf)) <= 0)
    {
        ERR_print_errors_fp(stderr);
        print_err("Unable to send mark request.");
        return false;
    }

    int nbytes = SSL_read(ssl, buf, lengthof(buf));
    while (nbytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        print_err("No response for mark request. (nbytes=%d)", nbytes);
        return false;
    }
    buf[nbytes] = 0;

    puts("----------------------------------------------------------------------------------------------------------");
    printf("Received Mark Response (nbytes=%d)\n", nbytes);
    puts(buf);
    puts("----------------------------------------------------------------------------------------------------------");

    if (!get_response_status(buf, status_code))
    {
        ERR_print_errors_fp(stderr);
        print_err("Couldn't read status code from response");
        return false;
    }

    return true;

    // int nbytes;
    // while ((nbytes = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0)
    // {
    //     buf[nbytes] = 0;

    //     puts("----------------------------------------------------------------------------------------------------------");
    //     puts("Timbra Response");
    //     puts(buf);
    //     puts("----------------------------------------------------------------------------------------------------------");

    //     int status_code = get_response_status(buf);
    //     if (status_code >= 0)
    //     {
    //         return status_code;
    //     }
    //     else
    //     {
    //         ERR_print_errors_fp(stderr);
    //         print_err("Couldn't read status code from response");
    //         continue;
    //     }
    // }

    // ERR_print_errors_fp(stderr);
    // print_err("No response for mark request. (nbytes=%d)", nbytes);
    // return ERR_STATUS_CODE;
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

bool save_cookies(char *src, char *dest, size_t dest_size)
{
    char *str_ptr = strstr(src, "Set-Cookie: ");
    if (!str_ptr)
    {
        print_err("Couldn't find cookie header line");
        return false;
    }

    str_ptr = strtok(str_ptr, " ");
    str_ptr = strtok(NULL, "\r\n");
    if (!str_ptr)
    {
        print_err("Couldn't find cookie header string token");
        return false;
    }

    if (strcpy_s(dest, dest_size, str_ptr))
        throw_err("Couldn't copy cookies to buffer");

    FILE *cookie_jar;
    if (fopen_s(&cookie_jar, COOKIES_FILENAME, "w"))
        throw_err("Couldn't open cookie jar " COOKIES_FILENAME);

    if (fputs(str_ptr, cookie_jar) == EOF)
        throw_err("Couldn't write cookies to cookie jar " COOKIES_FILENAME);

    fclose(cookie_jar);

    return true;
}

bool read_timbra_log(char *buf, size_t size)
{
    FILE *timbra_log;
    if (fopen_s(&timbra_log, TIMBRA_LOG_FILENAME, "r"))
    {
        print_err("Couldn't open " TIMBRA_LOG_FILENAME " file");
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
        print_err("Couldn't open " TIMBRA_LOG_FILENAME " file");
    }
    else
    {
        fclose(timbra_log);
    }

    return !ret;
}

bool get_response_status(char *res, uint16_t *status_code)
{
    char *str_ptr = strstr(res, "HTTP/1.1");
    if (!str_ptr)
    {
        print_err("Couldn't find status code header line");
        return false;
    }

    str_ptr = strtok(str_ptr, " ");
    str_ptr = strtok(NULL, " ");
    if (!str_ptr)
    {
        print_err("Couldn't find status code header string token");
        return false;
    }

    sscanf_s(str_ptr, "%hu", status_code);
    return true;
}

bool parse_scan_data(char *buf, ScanData *out)
{
    static const char delim[] = "-";

    char *str_token = strtok(buf, delim);
    if (!str_token)
        return false;

    if (!is_badge_code_valid(buf))
        return false;

    strncpy(out->code, str_token, lengthof(out->code));
    out->code_len = strlen(str_token);
    out->mark_in = out->code[0] == '0';

    str_token = strtok(NULL, delim);
    if (str_token)
        strncpy(out->name, str_token, lengthof(out->name));

    str_token = strtok(NULL, delim);
    if (str_token)
        strncpy(out->surname, str_token, lengthof(out->surname));

    return true;
}

bool is_badge_code_valid(const char *code_str)
{
    static const uint8_t CODE_LEN = 10;
    static const char VALID_PREFIXIES[][2] = {"01", "11"};
    static const uint8_t VALID_PREF_SIZE = countof(VALID_PREFIXIES);

    if (strlen(code_str) != CODE_LEN)
        return false;

    bool has_valid_pref = false;
    for (uint8_t i = 0; i < VALID_PREF_SIZE; ++i)
    {
        if (!strncmp(code_str, VALID_PREFIXIES[i], lengthof(VALID_PREFIXIES[i])))
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