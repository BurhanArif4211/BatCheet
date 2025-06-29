#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void handle_request(int client_socket);

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_socket, 10) < 0) {
        perror("listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Persistent server loop
    while (1) {
        // Accept incoming connection
        if ((client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
            perror("accept failed");
            continue;  // Skip failed connection
        }

        handle_request(client_socket);
        close(client_socket);  // Close client connection
    }

    close(server_socket);
    return 0;
}

void handle_request(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read;

    // Read HTTP request headers
    bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("read failed");
        return;
    }

    // Check for GET/POST
    char *method = strtok(buffer, " ");
    char *path = strtok(NULL, " ");
    printf("Method: %s\nPath: %s\n", method, path);

    // Handle GET request
    if (strcmp(method, "GET") == 0) {
        char response[] = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/plain\r\n\r\n"
                          "Hello from GET request!";
        write(client_socket, response, strlen(response));
    }
    // Handle POST request
    else if (strcmp(method, "POST") == 0) {
        // Find Content-Length header
        char *content_length_str = strstr(buffer, "Content-Length: ");
        int content_length = 0;
        if (content_length_str) {
            sscanf(content_length_str, "Content-Length: %d", &content_length);
        }

        // Read POST body if exists
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) body += 4;  // Skip header separator

        // Build response (echo body)
        char response_header[512];
        sprintf(response_header, 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %d\r\n\r\n",
                content_length);
        
        write(client_socket, response_header, strlen(response_header));
        if (content_length > 0) {
            write(client_socket, body, content_length);
        }
    } else {
        char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
        write(client_socket, response, strlen(response));
    }
}