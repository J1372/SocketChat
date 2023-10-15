#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <poll.h>
#include "util.h"

#define USERNAME_BUF_LENGTH 16

volatile sig_atomic_t running = 1;

struct ConnectionInfo
{
	int fd;
	char username[USERNAME_BUF_LENGTH];
};

void init_connection_info(struct ConnectionInfo* connection)
{
	connection->fd = -1;
	connection->username[0] = '\0';
}

struct addrinfo* get_addrinfo_list(const char* port)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6 
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE; // localhost
	
	struct addrinfo* res_list;
	
	int status = getaddrinfo(NULL, port, &hints, &res_list);
	if (status != 0)
	{
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return NULL;
	}
	
	return res_list;
}

int start_connecting(const char* port)
{
	struct addrinfo* res_list = get_addrinfo_list(port);
	for (struct addrinfo* it = res_list; it != NULL; it = it->ai_next)
	{
		int socket_listener = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		
		if (socket_listener == -1)
		{
			perror("Socket failed");
			continue;
		}
		if (connect(socket_listener, it->ai_addr, it->ai_addrlen) == -1)
		{
			perror("Connect failed");
			continue;
		}
		
		freeaddrinfo(res_list);
		return socket_listener;
	}
	
	if (res_list)
		freeaddrinfo(res_list);
	
	return -1;
}


int start_listening(const char* port)
{
	struct addrinfo* res_list = get_addrinfo_list(port);
	
	for (struct addrinfo* it = res_list; it != NULL; it = it->ai_next)
	{
		int socket_listener = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		
		if (socket_listener == -1)
		{
			perror("Socket failed");
			continue;
		}
		if (bind(socket_listener, it->ai_addr, it->ai_addrlen) == -1)
		{
			perror("Bind failed");
			continue;
		}
		if (listen(socket_listener, 20) == -1)
		{
			perror("Listen failed");
			continue;
		}
		
		freeaddrinfo(res_list);
		return socket_listener;
	}
	
	if (res_list)
		freeaddrinfo(res_list);
	
	return -1;
}

// returns in_addr* or in_addr6*
void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	else
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void print_connected_user(const struct ConnectionInfo* connection)
{
	struct sockaddr_storage who_sock_in;
	socklen_t who_sock_in_len = sizeof who_sock_in;
	int who = getpeername(connection->fd, (struct sockaddr*)&who_sock_in, &who_sock_in_len);
	if (who == -1)
	{
		perror("Could not print connected IP: Getpeername failed");
	}
	else
	{
		char presentation_buf[INET6_ADDRSTRLEN];
		
		if (inet_ntop(who_sock_in.ss_family, get_in_addr((struct sockaddr*) &who_sock_in), presentation_buf, sizeof presentation_buf) != NULL)
		{
			printf("%s connected from %s.\n", connection->username, presentation_buf);
		}
		else
		{
			perror("ERROR (inet_ntop):");
		}
	}
}

int accept_initial_connection(int listener)
{
	struct sockaddr_storage new_connection;
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	// returns size that it stored in new_connection.
	int conn_fd = accept(listener, (struct sockaddr*)&new_connection, &addr_len);
	
	if (conn_fd == -1)
	{
		perror("Accept failed");
		return -1;
	}
	
	close(listener); // we have accepted, so close initial socket listener.
	
	return conn_fd;
}

void interrupt_handler(int)
{
	running = 0;
}

void handle_receive(const struct ConnectionInfo* connection)
{
	char receive_msg_buf[1024];
	int bytes_received = recv(connection->fd, receive_msg_buf, sizeof receive_msg_buf, 0);
	if (bytes_received == -1)
		puts("Recv fail!");
	else if (bytes_received == 0)
	{
		puts("Remote closed connection.");
		running = 0;
	}
	else
	{
		receive_msg_buf[(int)fmin(bytes_received, 1023)] = '\0';
		printf("%s: %s\n", connection->username, receive_msg_buf);
	}
}

int send_all(int conn_fd, const char* buf, int to_send, int flags)
{
	int total_bytes_sent = 0;
	
	while (total_bytes_sent < to_send)
	{
		const char* cur_buf_pos = buf + total_bytes_sent;
		int bytes_left = to_send - total_bytes_sent;
		
		// Try to send remaining bytes.
		int bytes_sent = send(conn_fd, cur_buf_pos, bytes_left, flags);
		
		if (bytes_sent == -1) // send failed, allow caller to handle if want.
		{
			return total_bytes_sent;
		}
		else
		{
			total_bytes_sent += bytes_sent;
		}
	}
	
	return total_bytes_sent;
}  

void handle_user_msg(int conn_fd, const char* my_username)
{
	char user_msg_buf[1024];
	int bytes_read = read(STDIN_FILENO, user_msg_buf, sizeof user_msg_buf);
	
	// Truncate user msg if too big. No need to check if new line.
	int user_msg_length = bytes_read;
	if (bytes_read == sizeof user_msg_buf)
	{
		--user_msg_length;
	}
	else if (user_msg_length > 0 && user_msg_buf[user_msg_length - 1] == '\n') // Truncate trailing newline.
	{
		--user_msg_length;
	}
	
	// add null terminator for printing in sender's window.
	// this is not sent over socket.
	user_msg_buf[user_msg_length] = '\0';
	
	if (user_msg_length > 0)
	{
		int bytes_sent = send_all(conn_fd, user_msg_buf, user_msg_length, 0);
		if (bytes_sent == 0)
		{
			perror("Send failed");
		}
		else
		{
			// only print to self what was sent. 
			// bytes_sent <= user_msg_length < sizeof user_msg_buf.
			user_msg_buf[bytes_sent] = '\0';
			printf("%s: %s\n", my_username, user_msg_buf);
		}
		
	}
}

struct ConnectionInfo handle_host_setup(const char* port, const char* my_username)
{
	int first_conn_listener = start_listening(port);
	if (first_conn_listener == -1)
	{
		return (struct ConnectionInfo) { .fd=-1 };
	}
	
	// listening for connection.
	// accept 1
	
	struct ConnectionInfo connection;
	init_connection_info(&connection);
	
	while (connection.fd == -1 && running)
	{
		connection.fd = accept_initial_connection(first_conn_listener);
	}
	
	send(connection.fd, my_username, USERNAME_BUF_LENGTH, 0);
	recv(connection.fd, connection.username, USERNAME_BUF_LENGTH, 0);
	return connection;
}

struct ConnectionInfo handle_client_setup(const char* port, const char* my_username)
{
	struct ConnectionInfo connection;
	init_connection_info(&connection);
	
	
	connection.fd = start_connecting(port);
	if (connection.fd == -1)
	{
		return connection;
	}
	
	recv(connection.fd, connection.username, USERNAME_BUF_LENGTH, 0);
	send(connection.fd, my_username, USERNAME_BUF_LENGTH, 0);
	return connection;
}

int main()
{
	struct sigaction sa;
	sa.sa_handler = interrupt_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("Sigaction");
		return -1;
	}
	
	char username[USERNAME_BUF_LENGTH];
	prompt_string("Enter username:", username, sizeof username);
	
	int is_host = prompt_yes("Host?:");
	char port_str[8];
	prompt_string("Enter port:", port_str, sizeof port_str);
	
	struct ConnectionInfo connection;
	if (is_host)
	{
		connection = handle_host_setup(port_str, username);
		if (connection.fd == -1)
		{
			fprintf(stderr, "Could not listen!\n");
			return -1;
		}
	}
	else
	{
		connection = handle_client_setup(port_str, username);
		if (connection.fd == -1)
		{
			fprintf(stderr, "Could not connect!\n");
			return -1;
		}
	}
	
	print_connected_user(&connection);
	
	struct pollfd pfds[2];
	struct pollfd* stdin_pfd = pfds + 0;
	struct pollfd* sockin_pfd = pfds + 1;
	
	stdin_pfd->fd = STDIN_FILENO;
	stdin_pfd->events = POLLIN;
	sockin_pfd->fd = connection.fd;
	sockin_pfd->events = POLLIN;
	
	int poll_events = poll(pfds, sizeof(pfds) / sizeof(pfds[0]), 1000);
	while (poll_events != -1 && running)
	{
		if (stdin_pfd->revents & POLLIN)
		{
			// stdin input.
			handle_user_msg(connection.fd, username);
		}
		
		if (sockin_pfd->revents & POLLIN)
		{
			// Data to receive.
			handle_receive(&connection);
		}
		
		poll_events = poll(pfds, sizeof(pfds) / sizeof(pfds[0]), 1000);
	}
	
	close(connection.fd);
	
    return 0;
}
