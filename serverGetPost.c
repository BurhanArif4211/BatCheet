#define _POSIX_C_SOURCE 200809L  // For strtok_r
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <openssl/sha.h> // For password hashing
#include <ctype.h> // For URL decoding

#define PORT 8080
#define BUFFER_SIZE 4096
#define DB_NAME "auth.db"

// Function prototypes
void init_database();
void handle_request(int client_socket);
int verify_credentials(const char *username, const char *password);
int register_user(const char *username, const char *password);
sqlite3* open_database();
void send_json_response(int client_socket, int status_code, const char *status, const char *message);
void socket_err(const char *err);
void url_decode(char *str);//This function was written by deepseek to fix some error

int main() {
    init_database();

    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Creating socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        socket_err("socket failed");
    }

    // Initiallizing socket address
    server_addr.sin_family = AF_INET; // AF_INET indicates IP version 4
    server_addr.sin_addr.s_addr = INADDR_ANY; // INADDR_ANY use to connect to any local interface
    server_addr.sin_port = htons(PORT); // htons converts port to network byte order

    // Bind socket to port
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
        socket_err("bind failed");
    

    // Start listening for incoming connections
    if (listen(server_socket, 10) < 0) 
        socket_err("listen failed");

    printf("Server listening on port %d\n", PORT);

    while (1) {
        // Accept incoming connection
        if ((client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
            perror("accept failed");
            continue;
        }

        handle_request(client_socket);
        close(client_socket);  // Close client connection
    }

    close(server_socket);
    return 0;
}

// Create and initialize database with users table
void init_database() {
    sqlite3 *db;
    char *err_msg = 0;

    const char *sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL);";

    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Insert default admin user (password = "secret123")
    sql = "INSERT OR IGNORE INTO users (username, password_hash) VALUES "
          "('admin', 'd8578edf8458ce06fbc5bb76a58c5ca4');";
    sqlite3_exec(db, sql, 0, 0, &err_msg);

    sqlite3_close(db);
}

// Open database connection and return sqlite3* object
sqlite3* open_database() {
    sqlite3 *db;
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        fprintf(stderr, "Failed to open DB: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    return db;
}

// URL decode function to handle encoded characters
void url_decode(char *str) {
    if (!str) return;
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            *dst = (char) strtol(src + 1, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst = ' ';
            src++;
        } else {
            *dst = *src;
            src++;
        }
        dst++;
    }
    *dst = '\0';
}

void handle_request(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        perror("read failed");
        return;
    }
    buffer[bytes_read] = '\0';  // Ensure null-termination
    printf("Received request:\n%s\n", buffer);  // Debug print

    // Create a copy of the buffer for safe tokenization
    char buffer_copy[BUFFER_SIZE];
    strncpy(buffer_copy, buffer, BUFFER_SIZE - 1);
    buffer_copy[BUFFER_SIZE - 1] = '\0';

    // Parse method and path using strtok_r
    char *saveptr = NULL;
    char *method = strtok_r(buffer_copy, " ", &saveptr);
    char *path = strtok_r(NULL, " ", &saveptr);

    if (!method || !path) {
        send_json_response(client_socket, 400, "error", "Invalid request");
        return;
    }

    // Locate body in the original buffer
    char *body = strstr(buffer, "\r\n\r\n");
    if (body) {
        body += 4;  // Skip header section
        // Remove possible trailing newline characters
        char *end = body + strlen(body);
        while (end > body && (end[-1] == '\n' || end[-1] == '\r')) {
            *--end = '\0';
        }
    } else {
        body = NULL;
    }

    char username[50] = {0}, password[50] = {0};

    // Parse the body if it exists
    if (body && *body) {
        char *body_copy = strdup(body);  // Create a copy for safe tokenization
        char *saveptr2 = NULL;
        char *token = strtok_r(body_copy, "&", &saveptr2);
        
        while (token) {
            char *eq = strchr(token, '=');
            if (eq) {
                *eq = '\0'; // Split into key/value
                char *key = token;
                char *value = eq + 1;
                
                if (strcmp(key, "username") == 0) {
                    strncpy(username, value, 49);
                    username[49] = '\0';
                    url_decode(username);
                } else if (strcmp(key, "password") == 0) {
                    strncpy(password, value, 49);
                    password[49] = '\0';
                    url_decode(password);
                }
            }
            token = strtok_r(NULL, "&", &saveptr2);
        }
        free(body_copy);
    }

    // Print extracted values
    printf("Parsed Username: '%s'\n", username);
    printf("Parsed Password: '%s'\n", password);

    // Validate inputs
    if (strlen(username) == 0 || strlen(password) == 0) {
        send_json_response(client_socket, 400, "error", "Username and password required");
        return;
    }

    // Handle login
    if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
        int auth_result = verify_credentials(username, password);
        if (auth_result == 1) {
            send_json_response(client_socket, 200, "success", "Login successful");
        } else {
            send_json_response(client_socket, 401, "error", "Invalid credentials");
        }
        return;
    }

    // Handle register
    if (strcmp(method, "POST") == 0 && strcmp(path, "/register") == 0) {
        int reg_result = register_user(username, password);
        if (reg_result == 1) {
            send_json_response(client_socket, 200, "success", "User registered successfully");
        } else if (reg_result == -1) {
            send_json_response(client_socket, 409, "error", "Username already exists");
        } else {
            send_json_response(client_socket, 500, "error", "Registration failed");
        }
        return;
    }

    // Unsupported route
    send_json_response(client_socket, 404, "error", "Endpoint not found");
}

// Authenticate user by checking username and password hash
int verify_credentials(const char *username, const char *password) {
    sqlite3 *db = open_database();
    if (!db) return 0;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    char password_hash[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&password_hash[i*2], "%02x", hash[i]);
    }
    password_hash[64] = '\0';

    const char *sql = "SELECT 1 FROM users WHERE username = ? AND password_hash = ?;";
    sqlite3_stmt *stmt;
    int result = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = 1;  // Valid credentials
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

// Register user with hashed password into database
int register_user(const char *username, const char *password) {
    sqlite3 *db = open_database();
    if (!db) return 0;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    char password_hash[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&password_hash[i*2], "%02x", hash[i]);
    }
    password_hash[64] = '\0';

    const char *sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
    sqlite3_stmt *stmt;
    int result = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_DONE) {
            result = 1; // Success
        } else if (sqlite3_errcode(db) == SQLITE_CONSTRAINT) {
            result = -1; // Username exists
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

// Helper function to send JSON HTTP responses
void send_json_response(int client_socket, int status_code, const char *status, const char *message) {
    char response[BUFFER_SIZE];
    int len = snprintf(response, BUFFER_SIZE,
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        "{\"status\":\"%s\",\"message\":\"%s\"}\n",
        status_code, status, message);
    write(client_socket, response, len);
}

// Error handler for socket-related failures
void socket_err(const char *err) {
    perror(err);
    exit(EXIT_FAILURE);
}