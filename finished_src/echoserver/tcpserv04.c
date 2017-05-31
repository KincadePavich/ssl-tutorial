#include <wolfssl/ssl.h>
#include "unp.h"

static int cleanup; /* to handle shutdown */

void
sig_handler(const int sig)
{
    printf("\nSIGINT handled.\n");
    cleanup = 1;
    return;
}

void
str_echo(WOLFSSL* ssl)
{
    int n;
    char buf[MAXLINE];

    while ((n = wolfSSL_read(ssl, buf, MAXLINE)) > 0) {
        if(wolfSSL_write(ssl, buf, n) != n) {
            err_sys("wolfSSL_write failed");
        }
    }

    if (n < 0) {
        printf("wolfSSL_read error = %d\n", wolfSSL_get_error(ssl, n));
    }
    else if (n == 0) {
        printf("The peer has closed the connection.\n");
    }
}

int
main(int argc, char **argv)
{
    WOLFSSL_CTX*        ctx; /* define a wolfSSL context */
    WOLFSSL*            ssl;
	int					listenfd, connfd;
	pid_t				childpid;
	socklen_t			clilen;
	struct sockaddr_in	cliaddr, servaddr;
	char				buff[MAXLINE];
	int					optval;				/* flag value for setsockopt */
    struct sigaction    act, oact;

    /* Define a signal handler for when the user closes the program with CTRL+C.
       Also, turn off SA_RESTART so that the OS doesn't restart the call to
       accept() after the signal is handled. */
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, &oact);

    wolfSSL_Init(); /* initialize wolfSSL */

    /* Create the wolfSSL context */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    /* Load CA certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0) !=
            SSL_SUCCESS) {
        fprintf(stderr, "Error loading ../certs/ca-cert.pem, "
                "please check the file.\n");
        exit(EXIT_FAILURE);
    }

    /* Load server certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem",
                SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading ../certs/server-cert.pem, "
                "please check the file.\n");
        exit(EXIT_FAILURE);
    }

    /* Load Keys */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "../certs/server-key.pem",
                SSL_FILETYPE_PEM) != SSL_SUCCESS) {

    }

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	/* setsockopt: Eliminates "ERROR on binding: Address already in use"
     * error. */
	optval = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
               sizeof(int));

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(SERV_PORT);

	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));

	Listen(listenfd, LISTENQ);

	while (cleanup != 1) {
		clilen = sizeof(cliaddr);
		if ( (connfd = accept(listenfd, (SA *) &cliaddr, &clilen)) < 0)
		{
			if (errno == EINTR)
				continue;		/* back to for() */
			else
				err_sys("accept error");
		}

		printf("Connection from %s, port %d\n",
				inet_ntop(AF_INET, &cliaddr.sin_addr, buff, sizeof(buff)),
				ntohs(cliaddr.sin_port));

		if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "wolfSSL_new error.\n");
            exit(EXIT_FAILURE);
        }
        wolfSSL_set_fd(ssl, connfd);
        str_echo(ssl);		/* process the request */
        wolfSSL_free(ssl);
		Close(connfd);			/* close connected socket */
	}
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}
