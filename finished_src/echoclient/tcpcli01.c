#include <wolfssl/ssl.h>
#include "unp.h"

void
str_cli(FILE *fp, WOLFSSL* ssl)
{
	char	sendline[MAXLINE], recvline[MAXLINE];
    int n = 0;

	while (Fgets(sendline, MAXLINE, fp) != NULL) {

        if(wolfSSL_write(ssl, sendline, strlen(sendline)) != strlen(sendline)) {
            err_sys("wolfSSL_write failed");
        }

        if((n = wolfSSL_read(ssl, recvline, MAXLINE)) <= 0) {
            err_quit("wolfSSL_read error");
        }

        recvline[n] ='\0';
		Fputs(recvline, stdout);
	}
}

int
main(int argc, char **argv)
{
	WOLFSSL_CTX*        ctx; /* define a wolfSSL context */
    WOLFSSL*            ssl;
    int					sockfd;
	struct sockaddr_in	servaddr;

    wolfSSL_Init(); /* initialize wolfSSL */

    /* Create the wolfSSL context */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
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

	if (argc != 2)
		err_quit("usage: tcpcli <IPaddress>");

	sockfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERV_PORT);
	Inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

    /* Connect to socket file descriptor */
	Connect(sockfd, (SA *) &servaddr, sizeof(servaddr));

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }

    wolfSSL_set_fd(ssl, sockfd);

	str_cli(stdin, ssl);		/* do it all */

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
	exit(0);
}
