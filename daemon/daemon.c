/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <wordexp.h>

#include <certifier/base64.h>
#include <certifier/certifier.h>
#include <certifier/property_internal.h>

static int running           = 0;
static int counter           = 0;
static char * conf_file_name = NULL;
static char * pid_file_name  = NULL;
static char * cert_dir_list  = NULL;
static int pid_fd            = -1;
static char * app_name       = NULL;
static FILE * log_stream;

static char s_list_of_certs[256][256] = { 0 };

static Certifier * s_certifier;

/**
 * \brief Callback function for handling signals.
 * \param	sig	identifier of signal
 */
void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        fprintf(log_stream, "Debug: stopping daemon ...\n");
        /* Unlock and close lockfile */
        if (pid_fd != -1)
        {
            lockf(pid_fd, F_ULOCK, 0);
            close(pid_fd);
        }
        /* Try to delete lockfile */
        if (pid_file_name != NULL)
        {
            unlink(pid_file_name);
        }
        running = 0;
        /* Reset signal handling to default behavior */
        signal(SIGINT, SIG_DFL);
    }
    else if (sig == SIGHUP)
    {
        fprintf(log_stream, "Debug: reloading daemon config file ...\n");
        if (conf_file_name != NULL)
        {
            certifier_set_property(s_certifier, CERTIFIER_OPT_CFG_FILENAME, conf_file_name);
        }
        else
        {
            certifier_set_property(s_certifier, CERTIFIER_OPT_CFG_FILENAME, get_default_cfg_filename());
        }
    }
    else if (sig == SIGCHLD)
    {
        fprintf(log_stream, "Debug: received SIGCHLD signal\n");
    }
}

/**
 * \brief This function will daemonize this app
 */
static void daemonize()
{
    pid_t pid = 0;
    int fd;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Ignore signal sent from child to parent process */
    signal(SIGCHLD, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
    {
        close(fd);
    }

    /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
    stdin  = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");

    /* Try to write PID of daemon to lockfile */
    if (pid_file_name != NULL)
    {
        char str[256];
        pid_fd = open(pid_file_name, O_RDWR | O_CREAT, 0640);
        if (pid_fd < 0)
        {
            /* Can't open lockfile */
            exit(EXIT_FAILURE);
        }
        if (lockf(pid_fd, F_TLOCK, 0) < 0)
        {
            /* Can't lock file */
            exit(EXIT_FAILURE);
        }
        /* Get current PID */
        sprintf(str, "%d\n", getpid());
        /* Write PID to lockfile */
        write(pid_fd, str, strlen(str));
    }
}

static const char * get_filename_ext(const char * filename)
{
    const char * dot = strrchr(filename, '.');
    if (!dot || dot == filename)
    {
        return "";
    }
    return dot + 1;
}

static void refresh_list_of_certificates()
{
    if (cert_dir_list == NULL)
    {
        return;
    }

    size_t list_of_certs_idx = 0;

    char delim[]     = ":";
    char * directory = strtok(cert_dir_list, delim);

    memset(s_list_of_certs, 0, sizeof(s_list_of_certs));

    while (directory != NULL)
    {

        // perform shell-like expansion of characters such as ~
        wordexp_t exp_result;
        wordexp(directory, &exp_result, 0);
        const char * expanded_cert_dir = exp_result.we_wordv[0];

        size_t directory_len = strlen(expanded_cert_dir);

        if (directory_len - 1 >= sizeof(*s_list_of_certs))
        {
            return;
        }

        DIR * dir = opendir(expanded_cert_dir);
        if (dir != NULL)
        {
            // Nested directories are not handled.
            struct dirent * entry;
            while ((entry = readdir(dir)) != NULL)
            {
                const char * fileExtension = get_filename_ext(entry->d_name);
                if (strncmp(fileExtension, "p12", strlen("p12")) == 0)
                {
                    size_t offset       = directory_len;
                    size_t max_capacity = sizeof(s_list_of_certs[0]) - directory_len - 1;
                    size_t filename_len = strlen(entry->d_name);

                    strncpy(s_list_of_certs[list_of_certs_idx], expanded_cert_dir, directory_len);
                    strncpy(s_list_of_certs[list_of_certs_idx] + offset, "/",
                            2); // 2 to avoid warning about null character truncation
                    strncpy(s_list_of_certs[list_of_certs_idx] + offset + 1, entry->d_name, max_capacity);

                    // make sure that filename is null terminated (probably not needed, but keeping it for safety)
                    s_list_of_certs[list_of_certs_idx][directory_len + 1 + filename_len] = '\0';

                    ++list_of_certs_idx;
                }
            }
            closedir(dir);
        }

        directory = strtok(NULL, delim);
    }
}

static void log_list_of_certificates()
{
    for (size_t list_of_certs_idx = 0; *s_list_of_certs[list_of_certs_idx] != 0; ++list_of_certs_idx)
    {
        int ret = fprintf(log_stream, "Cert Path: %s\n", s_list_of_certs[list_of_certs_idx]);
        if (ret < 0)
        {
            syslog(LOG_ERR, "Can not write to log stream: %s, error: %s", (log_stream == stdout) ? "stdout" : "unknown_file_name",
                   strerror(errno));
            break;
        }
        ret = fflush(log_stream);
    }
}

static int renew_certificate(Certifier * certifier)
{
    char * tmp_crt = NULL;
    char * cert    = NULL;

    int rc = certifier_setup_keys(certifier);
    if (rc)
    {
        goto exit;
    }

    rc = certifier_create_x509_crt(certifier, &tmp_crt);
    if (rc)
    {
        goto exit;
    }
    else
    {
        if (tmp_crt != NULL)
        {
            const int cert_len = (int) XSTRLEN(tmp_crt);
            char * cert        = XMALLOC(base64_encode_len(cert_len));
            if (cert == NULL)
            {
                goto exit;
            }
            base64_encode(cert, (const unsigned char *) tmp_crt, cert_len);
            rc = certifier_set_property(certifier, CERTIFIER_OPT_CRT, cert);
            if (rc)
            {
                goto exit;
            }
        }
    }

    rc = certifier_renew_certificate(certifier);
    if (rc)
    {
        goto exit;
    }

exit:
    XFREE(tmp_crt);
    XFREE(cert);

    return rc;
}

static void try_renew_certificates(Certifier * certifier)
{
    for (size_t list_of_certs_idx = 0; *s_list_of_certs[list_of_certs_idx] != 0; ++list_of_certs_idx)
    {
        certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, s_list_of_certs[list_of_certs_idx]);
        // TODO: Implement keymgr exchange
        certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, "changeit");

        // check state
        int rc = certifier_get_device_certificate_status(certifier);
        // check validity
        rc |= certifier_get_device_registration_status(certifier);
        switch (rc)
        {
        case CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2:
            syslog(LOG_INFO, "Certificate from file %s status: Expired", s_list_of_certs[list_of_certs_idx]);
            break;
        case CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE:
            syslog(LOG_INFO, "Certificate from file %s status: About to Expire", s_list_of_certs[list_of_certs_idx]);
            break;
        case CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1:
            syslog(LOG_INFO, "Certificate from file %s status: Not yet valid. Not renewing it.",
                   s_list_of_certs[list_of_certs_idx]);
            continue;
        case 0:
            syslog(LOG_INFO, "Certificate from file %s status: Valid. Not renewing it.", s_list_of_certs[list_of_certs_idx]);
            continue;
        case CERTIFIER_ERR_GET_CERT_STATUS_REVOKED:
            syslog(LOG_INFO, "Certificate from file %s status: Revoked. Not renewing it.", s_list_of_certs[list_of_certs_idx]);
            continue;
        case CERTIFIER_ERR_GET_CERT_STATUS_UNKNOWN | CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE:
        case CERTIFIER_ERR_GET_CERT_STATUS_UNKNOWN:
        default:
            syslog(LOG_INFO, "Certificate from file %s status: Unknown. Not renewing it.", s_list_of_certs[list_of_certs_idx]);
            continue;
        }

        rc = renew_certificate(certifier);
        if (rc == 0)
        {
            fprintf(log_stream, "Certificate from file %s successfully renewed\n", s_list_of_certs[list_of_certs_idx]);
            fflush(log_stream);
            syslog(LOG_INFO, "Certificate from file %s successfully renewed", s_list_of_certs[list_of_certs_idx]);
        }
        else
        {
            fprintf(log_stream, "Certificate from file %s failed to be renewed\n", s_list_of_certs[list_of_certs_idx]);
            fflush(log_stream);
            syslog(LOG_ERR, "Certificate from file %s failed to be renewed", s_list_of_certs[list_of_certs_idx]);
        }
    }
}

/**
 * \brief Print help for this application
 */
void print_help(void)
{
    printf("\n Usage: %s [OPTIONS]\n\n", app_name);
    printf("  Options:\n");
    printf("   -h --help                 Print this help\n");
    printf("   -c --conf-file  filename  Read configuration from the file\n");
    printf("   -l --log-file   filename  Write logs to the file\n");
    printf("   -d --daemon               Daemonize this application\n");
    printf("   -p --pid-file   filename  PID file used by daemonized app\n");
    printf("   -x --cert-paths dir:list  Directory where certificates shall be monitored for expiry/renewal\n");
    printf("\n");
}

/* Main function */
int main(int argc, char * argv[])
{
    static struct option long_options[] = { { "conf-file", required_argument, 0, 'c' },
                                            { "log-file", required_argument, 0, 'l' },
                                            { "help", no_argument, 0, 'h' },
                                            { "daemon", no_argument, 0, 'd' },
                                            { "pid-file", required_argument, 0, 'p' },
                                            { "cert-paths", required_argument, 0, 'x' },
                                            { NULL, 0, 0, 0 } };
    int value, option_index = 0, ret;
    char * log_file_name = NULL;
    int start_daemonized = 0;

    app_name = argv[0];

    /* Try to process all command line arguments */
    while ((value = getopt_long(argc, argv, "c:l:t:p:x:dh", long_options, &option_index)) != -1)
    {
        switch (value)
        {
        case 'c':
            conf_file_name = strdup(optarg);
            break;
        case 'l':
            log_file_name = strdup(optarg);
            break;
        case 'p':
            pid_file_name = strdup(optarg);
            break;
        case 'x':
            cert_dir_list = strdup(optarg);
            break;
        case 'd':
            start_daemonized = 1;
            break;
        case 'h':
            print_help();
            return EXIT_SUCCESS;
        case '?':
            print_help();
            return EXIT_FAILURE;
        default:
            break;
        }
    }

    /* When daemonizing is requested at command line. */
    if (start_daemonized == 1)
    {
        /* It is also possible to use glibc function deamon()
         * at this point, but it is useful to customize your daemon. */
        daemonize();
    }

    /* Open system log and write message to it */
    openlog(argv[0], LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Started %s", app_name);

    /* Daemon will handle two signals */
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);

    /* Try to open log file to this daemon */
    if (log_file_name != NULL)
    {
        log_stream = fopen(log_file_name, "a+");
        if (log_stream == NULL)
        {
            syslog(LOG_ERR, "Can not open log file: %s, error: %s", log_file_name, strerror(errno));
            log_stream = stdout;
        }
    }
    else
    {
        log_stream = stdout;
    }

    /* This global variable can be changed in function handling signal */
    running = 1;

    /* Initialize and Setup libCertifier */
    s_certifier = certifier_new();
    if (s_certifier != NULL)
    {

        /* Read configuration from config file */
        if (conf_file_name != NULL)
        {
            certifier_set_property(s_certifier, CERTIFIER_OPT_CFG_FILENAME, conf_file_name);
        }
        else
        {
            certifier_set_property(s_certifier, CERTIFIER_OPT_CFG_FILENAME, get_default_cfg_filename());
        }

        if (cert_dir_list != NULL)
        {
            certifier_set_property(s_certifier, CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST, cert_dir_list);
        }

        /* Never ending loop of server */
        while (running == 1)
        {
            /* Debug print */
            ret = fprintf(log_stream, "Debug: %d\n", counter++);
            if (ret < 0)
            {
                syslog(LOG_ERR, "Can not write to log stream: %s, error: %s", (log_stream == stdout) ? "stdout" : log_file_name,
                       strerror(errno));
                break;
            }
            ret = fflush(log_stream);
            if (ret != 0)
            {
                syslog(LOG_ERR, "Can not fflush() log stream: %s, error: %s", (log_stream == stdout) ? "stdout" : log_file_name,
                       strerror(errno));
                break;
            }

            cert_dir_list = certifier_get_property(s_certifier, CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST);
            refresh_list_of_certificates();
            log_list_of_certificates();
            try_renew_certificates(s_certifier);

            // This is not safe at all... Certfier property needs to be refactored.
            int delay = (int) (size_t) certifier_get_property(s_certifier, CERTIFIER_OPT_AUTORENEW_INTERVAL);
            sleep(delay);
        }
    }

    certifier_destroy(s_certifier);

    /* Close log file, when it is used. */
    if (log_stream != stdout)
    {
        fclose(log_stream);
    }

    /* Write system log and close it. */
    syslog(LOG_INFO, "Stopped %s", app_name);
    closelog();

    /* Free allocated memory */
    if (conf_file_name != NULL)
        free(conf_file_name);
    if (log_file_name != NULL)
        free(log_file_name);
    if (pid_file_name != NULL)
        free(pid_file_name);
    if (cert_dir_list != NULL)
        free(cert_dir_list);

    return EXIT_SUCCESS;
}
