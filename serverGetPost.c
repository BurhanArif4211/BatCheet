#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <openssl/sha.h> // For password hashing

#define PORT 8080
#define BUFFER_SIZE 4096
#define DB_NAME "auth.db"

// Function prototypes
void init_database();
void handle_request(int client_socket);
int verify_credentials(const char *username, const char *password);

int main() {
 
    init_database();
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
void init_database() {
    sqlite3 *db;
    char *err_msg = 0;
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL);";
    
    // Open database connection
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
    
    // Create users table
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    // Insert sample user (password: "secret123")
    sql = "INSERT OR IGNORE INTO users (username, password_hash) VALUES "
          "('admin', 'd8578edf8458ce06fbc5bb76a58c5ca4');"; // SHA-256 of "secret123"
    sqlite3_exec(db, sql, 0, 0, &err_msg);
    
    sqlite3_close(db);
}

void handle_request(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    read(client_socket, buffer, BUFFER_SIZE - 1);

    // Parse method and path
    char *method = strtok(buffer, " ");
    char *path = strtok(NULL, " ");
    
    // Handle POST /login
    if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
        // Find content length
        char *cl_header = strstr(buffer, "Content-Length: ");
        int content_length = 0;
        if (cl_header) sscanf(cl_header, "Content-Length: %d", &content_length);
        
        // Extract body
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) body += 4;
        
        // Parse credentials (format: username=admin&password=secret123)
        char username[50] = {0};
        char password[50] = {0};
        
        if (body) {
            char *token = strtok(body, "&");
            while (token) {
                if (strstr(token, "username=")) sscanf(token, "username=%49[^&]", username);
                if (strstr(token, "password=")) sscanf(token, "password=%49[^&]", password);
                token = strtok(NULL, "&");
            }
        }
        
        // Verify credentials
        int auth_result = verify_credentials(username, password);
        char response[BUFFER_SIZE];
        
        if (auth_result == 1) {
            snprintf(response, BUFFER_SIZE,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{\"status\":\"success\",\"message\":\"Login successful\"}"
            );
        } else {
            snprintf(response, BUFFER_SIZE,
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{\"status\":\"error\",\"message\":\"Invalid credentials\"}"
            );
        }
        write(client_socket, response, strlen(response));
    }
    // ... [Other request handling] ...
}

int verify_credentials(const char *username, const char *password) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result = 0;
    
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        fprintf(stderr, "Database connection failed\n");
        return 0;
    }
    
    // Hash input password
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);
    
    char password_hash[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&password_hash[i*2], "%02x", hash[i]);
    }
    password_hash[64] = '\0';
    
    // Parameterized query to prevent SQL injection
    const char *sql = "SELECT 1 FROM users WHERE username = ? AND password_hash = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = 1; // Valid credentials
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}
