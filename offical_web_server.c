#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define PORT 8080
#define BUFFSIZE 1024

char* read_html_file(const char* filename){
    FILE* file=fopen(filename,"rb");
    if (file==NULL){
        return NULL;
    }
    fseek(file,0,SEEK_END);
    long file_length=ftell(file);
    fseek(file,0,SEEK_SET);
    //malloc
    char*buffer=(char *)malloc(file_length+1);
    if (buffer==NULL){
        fclose(file);
        return NULL;
    }
    fread(buffer,1,file_length,file);
    fclose(file);
    buffer[file_length]='\0';
    return buffer;
}


int main(){
    //init variables
    WSADATA wsa;
    SOCKET server_fd,client_fd;
    struct sockaddr_in server_addr,client_addr;
    char buffer[BUFFSIZE];
    SSL_CTX *ctx;
    SSL *ssl;

    //INIT FOR OPENSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //SSL CONTENT
    //create SSL context
    ctx=SSL_CTX_new(TLS_server_method());
    if (!ctx){
        ERR_print_errors_fp(stderr);
        return 1;
    }
    //load cert
    if (SSL_CTX_use_certificate_file(ctx,"server.crt",SSL_FILETYPE_PEM)<=0){
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }
    //load private key
    if (SSL_CTX_use_PrivateKey_file(ctx,"server.key",SSL_FILETYPE_PEM)<=0){
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }



    //init winsock
    if (WSAStartup(MAKEWORD(2,2),&wsa)!=0){
        fprintf(stderr,"Error Init Winsock: %d\n",WSAGetLastError());
        SSL_CTX_free(ctx);
        return 1;
    }
    //create server socket
    server_fd=socket(AF_INET,SOCK_STREAM,0);
    //check socket
    if (server_fd==INVALID_SOCKET){
        fprintf(stderr,"Error Creating Server Socket: %d\n",WSAGetLastError());
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }


    //asign address details
    server_addr.sin_addr.s_addr=INADDR_ANY;
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(PORT);
    
    //bind to socket
    if (bind(server_fd,(struct sockaddr*)&server_addr,sizeof(server_addr))==SOCKET_ERROR){
        fprintf(stderr,"Error Binding Socket: %d\n",WSAGetLastError());
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    //listen on socket
    if (listen(server_fd,SOMAXCONN)==SOCKET_ERROR){
        fprintf(stderr,"Error Listening on Socket: %d\n",WSAGetLastError());
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }


    //listen for accept
    while (1){
        int size_of_client=sizeof(client_addr);
        client_fd=accept(server_fd,(struct sockaddr*)&client_addr,&size_of_client);
        if (client_fd==INVALID_SOCKET){
            fprintf(stderr,"Error Accepting Socket: %d\n",WSAGetLastError());
            SSL_CTX_free(ctx);
            WSACleanup();
            return 1;
        }
        //SSL
        //create new ssl object
        ssl=SSL_new(ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            closesocket(client_fd);
            closesocket(server_fd);
            SSL_CTX_free(ctx);
            WSACleanup();
            return 1;
        }
        //set socket to ssl
        SSL_set_fd(ssl,client_fd);
        //perform handshake
        if (SSL_accept(ssl)<=0){
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client_fd);
            closesocket(server_fd);
            SSL_CTX_free(ctx);
            WSACleanup();
            return 1;
        }

        //recv
        int byte_recv=SSL_read(ssl,buffer,BUFFSIZE);
        if (byte_recv <= 0){
            if (byte_recv==0){
                printf("client disconnect");
            } else{
                //erros for negative
                int ssl_error = SSL_get_error(ssl, byte_recv); 
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    printf("SSL_read: Want read/write. Retrying later.\n");
                } else {
                    //open SSL Erros
                    fprintf(stderr, "SSL_read error: %d\n", ssl_error);
                    ERR_print_errors_fp(stderr); 
                }
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client_fd);
        } else if (byte_recv > 0){
            printf("Received %d bytes:\n", byte_recv);
            for (int i = 0; i < byte_recv; i++) {
                printf("%02X ", (unsigned char)buffer[i]);
            }
            printf("\n");
            buffer[byte_recv] = '\0';
            printf("%s",buffer);
            //now logic for string
            if (strstr(buffer,"GET / HTTP/1.1")!=NULL){
                char* html_content=read_html_file("index.html");
                if (html_content!=NULL){
                    char response_header[256];
                    sprintf(response_header, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n", strlen(html_content));
                    SSL_write(ssl, response_header, strlen(response_header));
                    SSL_write(ssl, html_content, strlen(html_content));
                    free(html_content);
                }else{
                    const char* error_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found";
                    SSL_write(ssl, error_response, strlen(error_response));
                }
                
            }}else {
            const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found";
            SSL_write(ssl, not_found_response, strlen(not_found_response));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client_fd);
    }
    closesocket(server_fd);
    closesocket(client_fd);
    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}