/* ssh-hkaudit - check that the known_hosts for a host are known */

#include <sys/socket.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include <libssh2.h>

enum { HKEXIT_OKAY, HKEXIT_ERR, HKEXIT_NETFAIL = 7, HKEXIT_MISMATCH = 10,
    HKEXIT_NOTFOUND, HKEXIT_CKFAILURE, HKEXIT_UNKNOWN
};

int Flag_NumericHost;           /* n - AI_NUMERICHOST */

void emit_help(void);

int main(int argc, char *argv[])
{
    int ch, exit_status, ret, save_errno, sock;
    char *reason;

    char *known_file;
    char *host;
    char *port;
    int portnum;
    int family = AF_UNSPEC;
    struct addrinfo hints, *target, *tmp;

    LIBSSH2_SESSION *session;
    LIBSSH2_KNOWNHOSTS *known;
    const char *fingerprint;
    size_t len;
    int type;

#ifdef __OpenBSD__
    if (pledge("dns inet rpath stdio", NULL) == -1)
        err(HKEXIT_ERR, "pledge failed");
#endif

    while ((ch = getopt(argc, argv, "h?46n")) != -1) {
        switch (ch) {
        case '4':
            family = AF_INET;
            break;
        case '6':
            family = AF_INET;
            break;
        case 'n':
            Flag_NumericHost = AI_NUMERICHOST;
            break;
        case 'h':
        case '?':
        default:
            emit_help();
            /* NOTREACHED */
        }
    }
    argc -= optind;
    argv += optind;

    known_file = argv[0];
    if (!known_file || *known_file == '\0')
        emit_help();
    host = argv[1];
    if (!host || *host == '\0')
        emit_help();
    port = argv[2];
    if (!port || *port == '\0')
        port = "22";

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_flags |= Flag_NumericHost;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    if ((ret = getaddrinfo(host, port, &hints, &target)))
        errx(HKEXIT_ERR, "getaddrinfo failed: %s", gai_strerror(ret));

    for (tmp = target; tmp; tmp = tmp->ai_next) {
        sock = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        if (sock == -1) {
            reason = "socket failed";
            continue;
        }
        if (connect(sock, tmp->ai_addr, tmp->ai_addrlen) == -1) {
            reason = "connect failed";
            save_errno = errno;
            close(sock);
            errno = save_errno;
            sock = -1;
            continue;
        }
        if (tmp->ai_family == AF_INET) {
            portnum = ((struct sockaddr_in *) tmp->ai_addr)->sin_port;
        } else if (tmp->ai_family == AF_INET6) {
            portnum = ((struct sockaddr_in6 *) tmp->ai_addr)->sin6_port;
        } else {
            // figure out how to get portnumber for it?
            errx(HKEXIT_ERR, "unknown socket family (%d)", tmp->ai_family);
        }
        break;                  /* connected */
    }
    if (sock == -1)
        err(HKEXIT_NETFAIL, "%s", reason);
    /* probably not necessary since going away after verify */
    //freeaddrinfo(target);

    if ((ret = libssh2_init(0)) != 0)
        errx(HKEXIT_ERR, "libssh2_init failed (%d)", ret);
    if ((session = libssh2_session_init()) == NULL)
        errx(HKEXIT_ERR, "libssh2_session_init failed");
    if ((ret = libssh2_session_handshake(session, sock)) != 0)
        errx(HKEXIT_ERR, "libssh2_session_handshake failed (%d)", ret);
    if ((known = libssh2_knownhost_init(session)) == NULL)
        errx(HKEXIT_ERR, "libssh2_knownhost_init failed");

    if ((ret =
         libssh2_knownhost_readfile(known, known_file,
                                    LIBSSH2_KNOWNHOST_FILE_OPENSSH)) < 0)
        errx(HKEXIT_ERR, "libssh2_knownhost_readfile failed (%d)", ret);

    if ((fingerprint = libssh2_session_hostkey(session, &len, &type)) == NULL)
        errx(HKEXIT_ERR, "libssh2_session_hostkey failed");

    int check = libssh2_knownhost_checkp(known, host, portnum, fingerprint, len,
                                         LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                                         LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                         NULL);
    switch (check) {
    case LIBSSH2_KNOWNHOST_CHECK_MATCH:
        exit_status = HKEXIT_OKAY;
        break;
    case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
        puts("mismatch");
        exit_status = HKEXIT_MISMATCH;
        break;
    case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
        puts("not found");
        exit_status = HKEXIT_NOTFOUND;
        break;
    case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
        puts("check failure");
        exit_status = HKEXIT_CKFAILURE;
    default:
	/* check libssh2_knownhost_check(3) for additions, maybe? */
        puts("unknown??");
        exit_status = HKEXIT_UNKNOWN;
    }

    libssh2_session_disconnect(session, "shutdown");
    /* the program is about to go away, so skip these */
    //libssh2_knownhost_free(known);
    //libssh2_session_free(session);
    //libssh2_exit();

    exit(exit_status);
}

void emit_help(void)
{
    fputs("Usage: ssh-hkaudit [-4|-6] [-n] known-hosts-file host [port]\n", stderr);
    exit(EX_USAGE);
}
