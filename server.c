#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sqlite3.h>
#include <ctype.h>

#define SERVER_PORT 2500

extern int errno;

typedef struct
{
    int thread_id;
    int client_fd;
    char active_user[64];
} client_ctx;

/* Thread function */
static void *client_handler(void *arg);

/* Protocol command processing */
static void process_command(client_ctx *ctx, const char *cmd, char *response);

/* Command handlers */
static void cmd_register_user(client_ctx *ctx, const char *username, const char *masterPass, char *response);
static void cmd_login_user(client_ctx *ctx, const char *username, const char *masterPass, char *response);
static void cmd_del_category(client_ctx *ctx, const char *catName, char *response);
static void cmd_new_category(client_ctx *ctx, const char *catName, char *response);
static void cmd_list_categories(client_ctx *ctx, char *response);
static void cmd_new_entry(client_ctx *ctx, const char *cat, const char *title, const char *usr, const char *url, const char *notes, const char *pass, char *response);
static void cmd_list_entries(client_ctx *ctx, const char *cat, char *response);
static void cmd_mod_entry(client_ctx *ctx, const char *oldTitle, const char *newTitle, const char *newUsr, const char *newURL, const char *newNotes, const char *newPass, char *response);
static void cmd_del_entry(client_ctx *ctx, const char *title, char *response);
static void cmd_logout_user(client_ctx *ctx, char *response);
static void cmd_register_user_with_security(client_ctx *ctx, const char *username, const char *masterPass, const char *securityQ, const char *securityA, char *response);
static void cmd_recover_password(client_ctx *ctx, const char *username, const char *securityA, char *response);
static void cmd_change_password(client_ctx *ctx, const char *username, const char *oldPass, const char *newPass, char *response);
static void cmd_see_security_question(client_ctx *ctx, const char *username, char *response);

/* Database init and ops */
static int init_db(const char *db_name);
static int db_register(const char *username, const char *hashpass);
static int db_register_with_security(const char *username, const char *securityQ, const char *hashpass, const char *hashAns);
static int db_verify_security_answer(const char *username, const char *hashAns);
static int db_login(client_ctx *ctx, const char *username, const char *hashpass);
static int db_create_category(const char *username, const char *catName);
static int db_fetch_categories(const char *username, char *out);
static int db_insert_entry(const char *username, const char *cat, const char *title, const char *usr, const char *url, const char *notes, const char *pass);
static int db_fetch_entries(const char *username, const char *cat, char *out);
static int db_fetch_entry_by_title(const char *username, const char *title, char *out);
static int db_update_entry(const char *username, const char *oldTitle, const char *newTitle, const char *newUsr, const char *newURL, const char *newNotes, const char *newPass);
static int db_remove_entry(const char *username, const char *title);
static int db_see_security_question(const char *username, char *out);
static int db_update_password(const char *username, const char *newPass);
static int db_fetch_user_by_username(const char *username);
static int db_fetch_category_by_name(const char *username, const char *catName, char *out);
static int db_remove_category(const char *username, const char *catName);

/* Simple hash for demonstration */
static unsigned long simple_hash(const char *str);
static const char *ulong_to_str(unsigned long val);

/* Util function for password check */
static int evaluate_password_strength(const char *pass, char *response);

int main()
{
    if (init_db("PasswordManager.db") != SQLITE_OK)
    {
        fprintf(stderr, "Database initialization failed.\n");
        return 1;
    }

    struct sockaddr_in server_addr, client_addr;
    int sd;

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Server socket error.\n");
        return errno;
    }

    int opt = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Bind error.\n");
        return errno;
    }

    if (listen(sd, 10) == -1)
    {
        perror("Listen error.\n");
        return errno;
    }

    printf("PasswordManager Server running on port %d...\n", SERVER_PORT);

    int i = 0;
    pthread_t threads[100];

    while (1)
    {
        socklen_t c_len = sizeof(client_addr);
        int client_fd = accept(sd, (struct sockaddr *)&client_addr, &c_len);
        if (client_fd < 0)
        {
            perror("Accept error.\n");
            continue;
        }

        client_ctx *ctx = (client_ctx *)malloc(sizeof(client_ctx));
        ctx->thread_id = i++;
        ctx->client_fd = client_fd;
        ctx->active_user[0] = '\0';

        pthread_create(&threads[i], NULL, client_handler, (void *)ctx);
    }

    close(sd);
    return 0;
}

static void *client_handler(void *arg)
{
    client_ctx *ctx = (client_ctx *)arg;
    pthread_detach(pthread_self());

    char buffer[4096];

    while (1)
    {
        int rbytes = read(ctx->client_fd, buffer, sizeof(buffer) - 1);
        if (rbytes <= 0)
        {
            perror("Client read error.\n");
            break;
        }
        buffer[rbytes] = '\0';

        if (strcmp(buffer, "EXIT") == 0)
        {
            printf("[Thread %d] Client requested disconnect.\n", ctx->thread_id);
            break;
        }

        char response[4096];
        response[0] = '\0';

        process_command(ctx, buffer, response);

        if (write(ctx->client_fd, response, strlen(response)) <= 0)
        {
            perror("Client write error.\n");
            break;
        }
    }

    close(ctx->client_fd);
    free(ctx);
    return NULL;
}

static void process_command(client_ctx *ctx, const char *cmd, char *response)
{
    // Split by '|'
    char copy[4096];
    strncpy(copy, cmd, sizeof(copy));
    copy[sizeof(copy) - 1] = '\0';

    char *tokens[16];
    int count = 0;
    char *tok = strtok(copy, "|");
    while (tok && count < 16)
    {
        tokens[count++] = tok;
        tok = strtok(NULL, "|");
    }

    // for (int i = 0; i<count; i++)
    // {
    //     printf("Token %d: %s\n", i, tokens[i]);
    // }

    if (count == 0)
    {
        strcpy(response, "Empty command.\n");
        return;
    }

    if (strcmp(tokens[0], "REGISTER") == 0 && count == 3)
    {
        cmd_register_user(ctx, tokens[1], tokens[2], response);
    }
    else if (strcmp(tokens[0], "LOGIN") == 0 && count == 3)
    {
        cmd_login_user(ctx, tokens[1], tokens[2], response);
    }
    else if (strcmp(tokens[0], "NEW_CAT") == 0 && count == 2)
    {
        cmd_new_category(ctx, tokens[1], response);
    }
    else if (strcmp(tokens[0], "LIST_CATS") == 0 && count == 1)
    {
        cmd_list_categories(ctx, response);
    }
    else if (strcmp(tokens[0], "NEW_ENTRY") == 0 && count == 7)
    {
        cmd_new_entry(ctx, tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6], response);
    }
    else if (strcmp(tokens[0], "LIST_ENTRIES") == 0 && count == 2)
    {
        cmd_list_entries(ctx, tokens[1], response);
    }
    else if (strcmp(tokens[0], "MOD_ENTRY") == 0 && count == 7)
    {
        cmd_mod_entry(ctx, tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6], response);
    }
    else if (strcmp(tokens[0], "DEL_ENTRY") == 0 && count == 2)
    {
        cmd_del_entry(ctx, tokens[1], response);
    }
    else if (strcmp(tokens[0], "LOGOUT") == 0 && count == 1)
    {
        cmd_logout_user(ctx, response);
    }
    else if (strcmp(tokens[0], "REGISTER_SEC") == 0 && count == 5)
    {
        cmd_register_user_with_security(ctx, tokens[1], tokens[2], tokens[3], tokens[4], response);
    }
    else if (strcmp(tokens[0], "SEC_QUESTION") == 0 && count == 2)
    {
        cmd_see_security_question(ctx, tokens[1], response);
    }
    else if (strcmp(tokens[0], "RECOVER_PASS") == 0 && count == 3)
    {
        cmd_recover_password(ctx, tokens[1], tokens[2], response);
    }
    else if (strcmp(tokens[0], "CHANGE_PASS") == 0 && count == 4)
    {
        cmd_change_password(ctx, tokens[1], tokens[2], tokens[3], response);
    }
    else if (strcmp(tokens[0], "DEL_CAT") == 0 && count == 2)
    {
        cmd_del_category(ctx, tokens[1], response);
    }
    else
    {
        strcpy(response, "Invalid command or parameters.\n");
    }
}

/* Command Handlers */

static int evaluate_password_strength(const char *pass, char *response)
{
    int len = strlen(pass);
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;

    for (int i = 0; i < len; ++i)
    {
        if (isdigit(pass[i]))
            has_digit = 1;
        else if (isupper(pass[i]))
            has_upper = 1;
        else if (islower(pass[i]))
            has_lower = 1;
        else if (ispunct(pass[i]))
            has_special = 1;
    }

    if (len >= 8 && has_upper && has_lower && has_digit && has_special)
    {
        strcpy(response, "Password strength: Strong\n");
        return 0;
    }
    else
    {
        strcpy(response, "Password strength: Weak - Consider using a longer password with uppercase, lowercase, digits, and special characters.\n");
        return 1;
    }
}

/* Integrate this into the registration command */
static void cmd_register_user(client_ctx *ctx, const char *username, const char *masterPass, char *response)
{
    char strength_response[256];
    if (username[0] == '\0' || masterPass[0] == '\0')
    {
        strcpy(response, "All fields are required.\n");
        return;
    }

    int exists = db_fetch_user_by_username(username);
    if (exists == 0)
    {
        strcpy(response, "User already exists.\n");
        return;
    }

    if (evaluate_password_strength(masterPass, strength_response) == 0)
    {
        strcat(response, strength_response);
    }
    else
    {
        strcat(response, strength_response);
        strcat(response, "\nMaster password not accepted.\n");
        return;
    }

    unsigned long hash = simple_hash(masterPass);
    const char *hash_str = ulong_to_str(hash);
    int rc = db_register(username, hash_str);
    if (rc == 0)
    {
        strcat(response, "Registration successful.\n");
    }
    else
    {
        strcat(response, "Registration failed, possibly user exists.\n");
    }
}

static void cmd_login_user(client_ctx *ctx, const char *username, const char *masterPass, char *response)
{
    unsigned long hash = simple_hash(masterPass);
    const char *hash_str = ulong_to_str(hash);

    if (ctx->active_user[0])
    {
        strcpy(response, "Already logged in.\n");
        return;
    }

    int rc = db_login(ctx, username, hash_str);
    if (rc == 0)
    {
        sprintf(response, "Login successful: %s\n", username);
    }
    else
    {
        strcpy(response, "Login failed: invalid credentials.\n");
    }
}

static void cmd_new_category(client_ctx *ctx, const char *catName, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    int exists = db_fetch_category_by_name(ctx->active_user, catName, response);
    if (exists == 0)
    {
        strcpy(response, "Category already exists.\n");
        return;
    }

    int rc = db_create_category(ctx->active_user, catName);
    if (rc == 0)
    {
        strcpy(response, "Category added.\n");
    }
    else
    {
        strcpy(response, "Failed to add category. It may already exist.\n");
    }
}

static void cmd_list_categories(client_ctx *ctx, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    char out[2048] = "";
    if (db_fetch_categories(ctx->active_user, out) == 0)
    {
        if (strlen(out) == 0)
        {
            strcpy(response, "No categories found.\n");
        }
        else
        {
            sprintf(response, "Categories:\n%s", out);
        }
    }
    else
    {
        strcpy(response, "Error retrieving categories.\n");
    }
}

static void cmd_new_entry(client_ctx *ctx, const char *cat, const char *title, const char *usr, const char *url, const char *notes, const char *pass, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    int exists = db_fetch_entry_by_title(ctx->active_user, title, response);
    if (exists == 0)
    {
        strcpy(response, "Entry with that title already exists.\n");
        return;
    }
    exists = db_fetch_category_by_name(ctx->active_user, cat, response);
    if (exists != 0)
    {
        strcpy(response, "Category not found.\n");
        return;
    }
    int rc = db_insert_entry(ctx->active_user, cat, title, usr, url, notes, pass);
    if (rc == 0)
    {
        strcpy(response, "Entry added.\n");
    }
    else
    {
        strcpy(response, "Failed to add entry.\n");
    }
}

static void cmd_list_entries(client_ctx *ctx, const char *cat, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    char out[4096] = "";
    if (db_fetch_entries(ctx->active_user, cat, out) == 0)
    {
        if (strlen(out) == 0)
        {
            strcpy(response, "No entries in that category.\n");
        }
        else
        {
            sprintf(response, "Entries:\n%s", out);
        }
    }
    else
    {
        strcpy(response, "Error retrieving entries.\n");
    }
}

static void cmd_mod_entry(client_ctx *ctx, const char *oldTitle, const char *newTitle, const char *newUsr, const char *newURL, const char *newNotes, const char *newPass, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    int exists = db_fetch_entry_by_title(ctx->active_user, oldTitle, response);
    if (exists != 0)
    {
        strcpy(response, "Entry not found.\n");
        return;
    }
    int rc = db_update_entry(ctx->active_user, oldTitle, newTitle, newUsr, newURL, newNotes, newPass);
    if (rc == 0)
    {
        strcpy(response, "Entry updated.\n");
    }
    else
    {
        strcpy(response, "Failed to update entry.\n");
    }
}

static void cmd_del_entry(client_ctx *ctx, const char *title, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    int exists = db_fetch_entry_by_title(ctx->active_user, title, response);
    if (exists != 0)
    {
        strcpy(response, "Entry not found.\n");
        return;
    }
    int rc = db_remove_entry(ctx->active_user, title);
    if (rc == 0)
    {
        strcpy(response, "Entry deleted.\n");
    }
    else
    {
        strcpy(response, "Failed to delete entry.\n");
    }
}

static void cmd_logout_user(client_ctx *ctx, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Not logged in.\n");
        return;
    }
    ctx->active_user[0] = '\0';
    strcpy(response, "Logged out.\n");
}

static void cmd_register_user_with_security(client_ctx *ctx, const char *username, const char *masterPass, const char *securityQ, const char *securityA, char *response)
{
    if (!username[0] || !masterPass[0] || !securityQ[0] || !securityA[0])
    {
        strcpy(response, "All fields are required.\n");
        return;
    }

    if (evaluate_password_strength(masterPass, response) == 1)
    {
        strcat(response, "Master password not accepted.\n");
        return;
    }

    int exists = db_fetch_user_by_username(username);
    if (exists == 0)
    {
        strcpy(response, "User already exists.\n");
        return;
    }

    unsigned long hashPass = simple_hash(masterPass);
    unsigned long hashAns = simple_hash(securityA);

    char hashPassStr[32], hashAnsStr[32];
    snprintf(hashPassStr, sizeof(hashPassStr), "%lu", hashPass);
    snprintf(hashAnsStr, sizeof(hashAnsStr), "%lu", hashAns);


    int rc = db_register_with_security(username, securityQ, hashPassStr, hashAnsStr);
    if (rc == 0)
    {
        strcpy(response, "Registration successful.\n");
    }
    else
    {
        strcpy(response, "Registration failed, possibly user exists.\n");
    }
}

static void cmd_see_security_question(client_ctx *ctx, const char *username, char *response)
{
    if (ctx->active_user[0])
    {
        strcpy(response, "Logout required.\n");
        return;
    }

    if (!username[0])
    {
        strcpy(response, "Username is required.\n");
        return;
    }

    int exists = db_fetch_user_by_username(username);
    if (exists != 0)
    {
        strcpy(response, "User not found.\n");
        return;
    }

    char securityQ[256];
    int rc = db_see_security_question(username, securityQ);
    if (rc == 0)
    {
        sprintf(response, "Security question: %s\n", securityQ);
    }
    else
    {
        strcpy(response, "User does not have a security question.\n");
    }
}

// This function will set the password of the user to "password" if the security answer is correct
static void cmd_recover_password(client_ctx *ctx, const char *username, const char *securityA, char *response)
{
    if (ctx->active_user[0])
    {
        strcpy(response, "Logout required.\n");
        return;
    }

    if (!username[0] || !securityA[0])
    {
        strcpy(response, "All fields are required.\n");
        return;
    }

    int exists = db_fetch_user_by_username(username);
    if (exists != 0)
    {
        strcpy(response, "User not found.\n");
        return;
    }

    char * buffer = malloc(256);
    int has_security = db_see_security_question(username, buffer);
    if (has_security != 0)
    {
        strcpy(response, "User does not have a security question.\n");
        return;
    }

    unsigned long hashAns = simple_hash(securityA);

    int rc = db_verify_security_answer(username, ulong_to_str(hashAns));
    if (rc == 0)
    {
        rc = db_update_password(username, ulong_to_str(simple_hash("password")));
        if (rc == 0)
        {
            strcpy(response, "Password reset to 'password'.\n");
        }
        else
        {
            strcpy(response, "Failed to reset password.\n");
        }
    }
    else
    {
        strcpy(response, "Invalid security answer.\n");
    }
}

static void cmd_change_password(client_ctx *ctx, const char *username, const char *oldPass, const char *newPass, char *response)
{
    if (ctx->active_user[0])
    {
        strcpy(response, "Logout required.\n");
        return;
    }

    if (!username[0] || !oldPass[0] || !newPass[0])
    {
        strcpy(response, "All fields are required.\n");
        return;
    }

    int exists = db_fetch_user_by_username(username);
    if (exists != 0)
    {
        strcpy(response, "User not found.\n");
        return;
    }

    if (evaluate_password_strength(newPass, response) == 1)
    {
        strcat(response, "New password not accepted.\n");
        return;
    }

    unsigned long hashOld = simple_hash(oldPass);
    unsigned long hashNew = simple_hash(newPass);

    // Check old password
    int rc = db_login(ctx, username, ulong_to_str(hashOld));
    if (rc != 0)
    {
        strcpy(response, "Invalid old password.\n");
        return;
    }

    // Update password
    rc = db_update_password(username, ulong_to_str(hashNew));
    if (rc == 0)
    {
        strcpy(response, "Password updated.\n");
    }
    else
    {
        strcpy(response, "Failed to update password.\n");
    }
}

static void cmd_del_category(client_ctx *ctx, const char *catName, char *response)
{
    if (!ctx->active_user[0])
    {
        strcpy(response, "Login required.\n");
        return;
    }
    int exists = db_fetch_category_by_name(ctx->active_user, catName, response);
    if (exists != 0)
    {
        strcpy(response, "Category not found.\n");
        return;
    }
    int rc = db_remove_category(ctx->active_user, catName);
    if (rc == 0)
    {
        strcpy(response, "Category deleted.\n");
    }
    else
    {
        strcpy(response, "Failed to delete category.\n");
    }
}

/* Database setup and operations */

static int init_db(const char *db_name)
{
    sqlite3 *db;
    char *err_msg = NULL;
    int rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return rc;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS Users ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Username TEXT UNIQUE, "
        "MasterHash TEXT NOT NULL, "
        "SecurityQuestion TEXT, "
        "SecurityAnswerHash TEXT);"

        "CREATE TABLE IF NOT EXISTS Categories ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Name TEXT, "
        "UserID INTEGER, "
        "UNIQUE(Name, UserID));"

        "CREATE TABLE IF NOT EXISTS Entries ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Title TEXT, "
        "EntryUser TEXT, "
        "URL TEXT, "
        "Notes TEXT, "
        "PassVal TEXT, "
        "UserID INTEGER, "
        "CategoryID INTEGER, "
        "UNIQUE(Title, UserID));";

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return rc;
    }

    sqlite3_close(db);
    return SQLITE_OK;
}

static int db_register(const char *username, const char *hashpass)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO Users (Username, MasterHash) VALUES ('%s','%s');", username, hashpass);

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);

    return rc == SQLITE_OK ? 0 : 1;
}

static int db_register_with_security(const char *username, const char *securityQ, const char *hashpass, const char *hashAns)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO Users (Username, MasterHash, SecurityQuestion, SecurityAnswerHash) VALUES ('%s','%s','%s','%s');", username, hashpass, securityQ, hashAns);

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK)
    {
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);

    return rc == SQLITE_OK ? 0 : 1;
}

static int db_see_security_question(const char *username, char *out)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT SecurityQuestion FROM Users WHERE Username=?;";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);

    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        if (sqlite3_column_text(res, 0) == NULL)
        {
            sqlite3_finalize(res);
            sqlite3_close(db);
            return 1;
        }
        strcpy(out, (const char *)sqlite3_column_text(res, 0));
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 1;
}

static int db_verify_security_answer(const char *username, const char *hashAns)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT ID FROM Users WHERE Username=? AND SecurityAnswerHash=?;";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);

    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, hashAns, -1, SQLITE_STATIC);

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 1;
}

static int db_login(client_ctx *ctx, const char *username, const char *hashpass)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT ID FROM Users WHERE Username=? AND MasterHash=?;";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);

    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, hashpass, -1, SQLITE_STATIC);

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        strncpy(ctx->active_user, username, sizeof(ctx->active_user) - 1);
        ctx->active_user[sizeof(ctx->active_user) - 1] = '\0';
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 1;
}

static int db_create_category(const char *username, const char *catName)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt =
        "INSERT INTO Categories (Name, UserID) VALUES "
        "(?, (SELECT ID FROM Users WHERE Username=?));";

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, catName, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }
    sqlite3_finalize(res);
    sqlite3_close(db);

    return rc == SQLITE_DONE ? 0 : 1;
}

static int db_fetch_categories(const char *username, char *out)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT Name FROM Categories WHERE UserID=(SELECT ID FROM Users WHERE Username=?);";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);

    while ((rc = sqlite3_step(res)) == SQLITE_ROW)
    {
        strcat(out, (const char *)sqlite3_column_text(res, 0));
        strcat(out, "\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
}

static int db_fetch_entry_by_title(const char *username, const char *title, char *out)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt =
        "SELECT Title, EntryUser, URL, Notes, PassVal FROM Entries "
        "WHERE Title=? AND UserID=(SELECT ID FROM Users WHERE Username=?);";

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, title, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
        if (rc == SQLITE_ROW)
        {
            snprintf(out, 512, "Title:%s, User:%s, URL:%s, Notes:%s, Pass:%s\n",
                     sqlite3_column_text(res, 0),
                     sqlite3_column_text(res, 1),
                     sqlite3_column_text(res, 2),
                     sqlite3_column_text(res, 3),
                     sqlite3_column_text(res, 4));
        }
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc == SQLITE_ROW ? 0 : 1;
}

static int db_insert_entry(const char *username, const char *cat, const char *title, const char *usr, const char *url, const char *notes, const char *pass)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt =
        "INSERT INTO Entries (Title, EntryUser, URL, Notes, PassVal, UserID, CategoryID) "
        "VALUES (?, ?, ?, ?, ?, "
        "(SELECT ID FROM Users WHERE Username=?), "
        "(SELECT ID FROM Categories WHERE Name=? AND UserID=(SELECT ID FROM Users WHERE Username=?)));";

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, title, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, usr, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 3, url, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 4, notes, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 5, pass, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 6, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 7, cat, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 8, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : 1;
}

static int db_fetch_entries(const char *username, const char *cat, char *out)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt =
        "SELECT Title, EntryUser, URL, Notes, PassVal FROM Entries "
        "WHERE UserID=(SELECT ID FROM Users WHERE Username=?) "
        "AND CategoryID=(SELECT ID FROM Categories WHERE Name=? AND UserID=(SELECT ID FROM Users WHERE Username=?));";

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, cat, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 3, username, -1, SQLITE_STATIC);

        while ((rc = sqlite3_step(res)) == SQLITE_ROW)
        {
            char line[512];
            snprintf(line, sizeof(line), "Title:%s, User:%s, URL:%s, Notes:%s, Pass:%s\n",
                     sqlite3_column_text(res, 0),
                     sqlite3_column_text(res, 1),
                     sqlite3_column_text(res, 2),
                     sqlite3_column_text(res, 3),
                     sqlite3_column_text(res, 4));
            strcat(out, line);
        }
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
}

static int db_update_entry(const char *username, const char *oldTitle, const char *newTitle, const char *newUsr, const char *newURL, const char *newNotes, const char *newPass)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt =
        "UPDATE Entries SET Title=?, EntryUser=?, URL=?, Notes=?, PassVal=? "
        "WHERE Title=? AND UserID=(SELECT ID FROM Users WHERE Username=?);";

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, newTitle, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, newUsr, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 3, newURL, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 4, newNotes, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 5, newPass, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 6, oldTitle, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 7, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    int changes = sqlite3_changes(db);
    sqlite3_finalize(res);
    sqlite3_close(db);
    return (rc == SQLITE_DONE && changes > 0) ? 0 : 1;
}

static int db_update_password(const char *username, const char *newPass)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "UPDATE Users SET MasterHash=? WHERE Username=?;";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, newPass, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : 1;
}

static int db_remove_entry(const char *username, const char *title)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "DELETE FROM Entries WHERE Title=? AND UserID=(SELECT ID FROM Users WHERE Username=?);";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, title, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : 1;
}

static int db_fetch_user_by_username(const char *username)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT ID FROM Users WHERE Username=?;";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 1;
}

static int db_fetch_category_by_name(const char *username, const char *catName, char *out)
{
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    const char *stmt = "SELECT ID FROM Categories WHERE Name=? AND UserID=(SELECT ID FROM Users WHERE Username=?);";
    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(res, 1, catName, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 1;
}


// This function will delete the category and any entries associated with it
static int db_remove_category(const char *username, const char *catName)
{
    const char *stmt = "DELETE FROM Entries WHERE CategoryID=(SELECT ID FROM Categories WHERE Name=? AND UserID=(SELECT ID FROM Users WHERE Username=?));";
    sqlite3 *db;
    sqlite3_open("PasswordManager.db", &db);

    sqlite3_stmt *res;
    int rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, catName, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    if (rc != SQLITE_DONE)
    {
        return 1;
    }

    stmt = "DELETE FROM Categories WHERE Name=? AND UserID=(SELECT ID FROM Users WHERE Username=?);";
    sqlite3_open("PasswordManager.db", &db);

    rc = sqlite3_prepare_v2(db, stmt, -1, &res, NULL);
    if (rc == SQLITE_OK)
    {
        sqlite3_bind_text(res, 1, catName, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, username, -1, SQLITE_STATIC);

        rc = sqlite3_step(res);
    }

    sqlite3_finalize(res);

    return rc == SQLITE_DONE ? 0 : 1;
}

/* Simple hashing for demonstration */
static unsigned long simple_hash(const char *str)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*str++))
        h = ((h << 5) + h) + c;
    return h;
}
static const char tmp_buf[32];
static const char *ulong_to_str(unsigned long val)
{
    static char buf[32];
    snprintf(buf, sizeof(buf), "%lu", val);
    return buf;
}
