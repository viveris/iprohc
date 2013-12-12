/*
 * This file is part of iprohc.
 *
 * iprohc is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 *
 * iprohc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file   session.h
 * @brief  The generic part of the session shared by server and client
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "session.h"

#include "log.h"

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/timerfd.h>


/**
 * @brief Initialize the given generic session
 *
 * @param session             The session to initialize
 * @param start_ctrl          The function that sends initial control message
 * @param handle_ctrl_msg     The function that handles received control messages
 * @param stop_ctrl           The function that sends final control message
 * @param handle_ctrl_opaque  The private data for the control message handler
 * @param tls_type            The type of TLS endpoint: GNUTLS_CLIENT or GNUTLS_SERVER
 * @param tls_cred            The credentials to use for the TLS session
 * @param priority_cache      The TLS priority cache
 * @param ctrl_socket         The TCP socket used for the control channel
 * @param local_addr          The IP address of the local endpoint
 * @param remote_addr         The IP address of the remote endpoint
 * @param raw_socket          The RAW socket to use to send packets to remote endpoint
 * @param tun_fd              The file descriptor of the local TUN interface
 * @param keepalive_timeout   The timeout (in seconds) for keepalive packets
 * @return                    true if session was successfully initialized,
 *                            false if a problem occurred
 */
bool iprohc_session_new(struct iprohc_session *const session,
                        iprohc_session_start_t start_ctrl,
                        iprohc_session_handler_t handle_ctrl_msg,
                        iprohc_session_start_t stop_ctrl,
                        void *const handle_ctrl_opaque,
                        const gnutls_connection_end_t tls_type,
                        gnutls_certificate_credentials_t tls_cred,
                        gnutls_priority_t priority_cache,
                        const int ctrl_socket,
                        const struct in_addr local_addr,
                        const struct sockaddr_in remote_addr,
                        const int raw_socket,
                        const int tun_fd,
                        const size_t keepalive_timeout)
{
	assert(session >= 0);
	assert(ctrl_socket >= 0);
	assert(raw_socket >= 0);
	assert(tun_fd >= 0);

	/* init the debug prefix */
	if(inet_ntop(AF_INET, &(remote_addr.sin_addr), session->dst_addr_str,
	             INET_ADDRSTRLEN) == NULL)
	{
		trace(LOG_ERR, "failed to convert address to string: %s (%d)",
		      strerror(errno), errno);
		goto error;
	}
	trace(LOG_INFO, "[%s] new connection from %s:%d",
	      session->dst_addr_str, session->dst_addr_str,
	      ntohs(remote_addr.sin_port));

	/* init session attributes */
	trace(LOG_DEBUG, "[%s] new session", session->dst_addr_str);
	session->tcp_socket = ctrl_socket;
	session->start_ctrl = start_ctrl;
	session->handle_ctrl_msg = handle_ctrl_msg;
	session->stop_ctrl = stop_ctrl;
	session->handle_ctrl_opaque = handle_ctrl_opaque;
	session->local_address = local_addr;
	session->src_addr.s_addr = INADDR_ANY;
	session->dst_addr = remote_addr.sin_addr;
	session->status = IPROHC_SESSION_CONNECTING;
	session->thread_tunnel = -1;

	/* Initialize TLS session */
	gnutls_init(&session->tls_session, tls_type);
	if(tls_type == GNUTLS_SERVER)
	{
		gnutls_priority_set(session->tls_session, priority_cache);
	}
	else if(tls_type == GNUTLS_CLIENT)
	{
		const int protocol_priority[] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
		const int cipher_priority[] = { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR, 0};
		const int comp_priority[] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
		const int kx_priority[] = { GNUTLS_KX_RSA, 0 };
		const int mac_priority[] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
		gnutls_protocol_set_priority(session->tls_session, protocol_priority);
		gnutls_cipher_set_priority(session->tls_session, cipher_priority);
		gnutls_compression_set_priority(session->tls_session, comp_priority);
		gnutls_kx_set_priority(session->tls_session, kx_priority);
		gnutls_mac_set_priority(session->tls_session, mac_priority);
	}
	gnutls_credentials_set(session->tls_session, GNUTLS_CRD_CERTIFICATE, tls_cred);
	gnutls_certificate_server_set_request(session->tls_session, GNUTLS_CERT_REQUEST);

	/* create keepalive timer */
	session->keepalive_timer_fd = timerfd_create(CLOCK_REALTIME, 0);
	if(session->keepalive_timer_fd < 0)
	{
		trace(LOG_ERR, "[client %s] failed to create keepalive timer: %s (%d)",
		      session->dst_addr_str, strerror(errno), errno);
		goto tls_deinit;
	}

	/* arm keepalive timer */
	if(!iprohc_session_update_keepalive(session, keepalive_timeout))
	{
		trace(LOG_ERR, "[client %s] failed to update the keepalive timeout to "
		      "%zu seconds", session->dst_addr_str, keepalive_timeout);
		goto close_keepalive_timer;
	}
	session->keepalive_misses = 0;

	AO_store_release_write(&(session->is_thread_running), 0);

	return true;

close_keepalive_timer:
	close(session->keepalive_timer_fd);
tls_deinit:
	gnutls_deinit(session->tls_session);
error:
	return false;
}


/**
 * @brief Reset the given generic session
 *
 * @param session  The session to reset
 * @return         true if the session was successfully reset,
 *                 false if a problem occurred
 */
bool iprohc_session_free(struct iprohc_session *const session)
{
	/* stop and destroy keepalive timer */
	close(session->keepalive_timer_fd);
	session->keepalive_timer_fd = -1;

	/* free TLS resources */
	gnutls_deinit(session->tls_session);

	/* reset source and destination addresses */
	memset(&(session->dst_addr), 0, sizeof(struct in_addr));
	memset(&(session->dst_addr_str), 0, INET_ADDRSTRLEN);
	memset(&(session->src_addr), 0, sizeof(struct in_addr));

	/* close TCP socket */
	close(session->tcp_socket);
	session->tcp_socket = -1;

	return true;
}


/**
 * @brief Change the timeout of the keepalive for control channel
 *
 * @param session  The session to update
 * @param timeout  The new keepalive timeout (in seconds)
 * @return         true if the update is successful,
 *                 false if a problem occurs
 */
bool iprohc_session_update_keepalive(struct iprohc_session *const session,
                                     const size_t timeout)
{
	struct itimerspec period;
	int ret;

	/* send keepalive 3 times more often than the timeout */
	if(timeout == 0)
	{
		period.it_value.tv_sec = 0;
	}
	else
	{
		period.it_value.tv_sec = timeout / 3;
		if(period.it_value.tv_sec == 0)
		{
			period.it_value.tv_sec = 1;
		}
	}
	period.it_value.tv_nsec = 0;
	period.it_interval.tv_sec = period.it_value.tv_sec;
	period.it_interval.tv_nsec = 0;

	if(period.it_value.tv_sec == 0)
	{
		trace(LOG_DEBUG, "[client %s] de-arm keepalive timer",
		      session->dst_addr_str);
	}
	else
	{
		trace(LOG_DEBUG, "[client %s] (re-)arm keepalive timer to %zu seconds",
		      session->dst_addr_str, period.it_value.tv_sec);
	}

	/* arm keepalive timer with the new value */
	ret = timerfd_settime(session->keepalive_timer_fd, 0, &period, NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[client %s] failed to arm keepalive timer with a "
		      "%zu-second period: %s (%d)", session->dst_addr_str,
		      period.it_value.tv_sec, strerror(errno), errno);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Start the main loop of the session
 * 
 * @param session  A client session
 * @return         true if the session loop was successfully started,
 *                 false if a problem occurred
 */
bool iprohc_session_start(struct iprohc_session *const session)
{
	const size_t stack_size = 100 * 1024;
	int ret;

	ret = pipe(session->p2c);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create a communication pipe between main "
		      "thread and client thread: %s (%d)", strerror(errno), errno);
		goto error;
	}

	AO_store_release_write(&(session->is_thread_running), 1);

	/* reduce stack of client threads to avoid using too much memory:
	 *  - allocate stack
	 *  - assign it to the new thread */
	ret = posix_memalign(&session->thread_stack, sysconf(_SC_PAGESIZE), stack_size);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create the client tunnel thread: failed to "
		      "allocate stack memory: %s (%d)", strerror(ret), ret);
		goto release_lock;
	}
	ret = pthread_attr_init(&session->thread_attr);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create the client tunnel thread: failed to "
		      "init thread attributes: %s (%d)", strerror(ret), ret);
		goto free_stack;
	}
	ret = pthread_attr_setstack(&session->thread_attr, session->thread_stack,
	                            stack_size);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create the client tunnel thread: failed to "
		      "assign stack memory to thread: %s (%d)", strerror(ret), ret);
		goto destroy_thread_attrs;
	}

	/* Go threads, go ! */
	ret = pthread_create(&(session->thread_tunnel), NULL,
	                     iprohc_tunnel_run, session);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create the client tunnel thread: %s (%d)",
		      strerror(ret), ret);
		goto free_stack;
	}

	return true;

destroy_thread_attrs:
	ret = pthread_attr_destroy(&session->thread_attr);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to destroy thread attributes: %s (%d)",
		      strerror(ret), ret);
	}
free_stack:
	free(session->thread_stack);
release_lock:
	AO_store_release_write(&(session->is_thread_running), 0);
/*close_pipe:*/
	close(session->p2c[1]);
	close(session->p2c[0]);
error:
	return false;
}


/**
 * @brief Stop the main loop of the session
 * 
 * @param session  A client session
 * @return         true if the session loop was successfully stopped,
 *                 false if a problem occurred
 */
bool iprohc_session_stop(struct iprohc_session *const session)
{
	int ret;

	/* stop thread if running */
	if(AO_load_acquire_read(&(session->is_thread_running)))
	{
		/* ask for thread to stop (close the write side of the pipe) */
		trace(LOG_ERR, "[main] ask client %s to stop", session->dst_addr_str);
	}
	if(session->p2c[1] >= 0)
	{
		close(session->p2c[1]);
		session->p2c[1] = -1;
	}

	/* wait for thread to stop */
	trace(LOG_ERR, "[main] wait for client %s to stop", session->dst_addr_str);
	pthread_join(session->thread_tunnel, NULL);

	/* free the thread attributes and the thread stack */
	ret = pthread_attr_destroy(&session->thread_attr);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to destroy thread attributes: %s (%d)",
		      strerror(ret), ret);
	}
	free(session->thread_stack);

	/* close the remaining read side of the pipe */
	close(session->p2c[0]);

	return true;
}

