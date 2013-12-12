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

#ifndef IPROHC_COMMON_SESSION__H
#define IPROHC_COMMON_SESSION__H

#include "rohc_tunnel.h"

#include <netinet/in.h>
#include <pthread.h>
#include <atomic_ops.h>
#include <gnutls/gnutls.h>


struct iprohc_session;


/** The different session statuses */
typedef enum
{
	IPROHC_SESSION_PENDING_DELETE  = 0,  /**< The session can be deleted */
	IPROHC_SESSION_CONNECTING      = 1,  /**< The session is currently connecting */
	IPROHC_SESSION_CONNECTED       = 2,  /**< The session successfully connected */
} iprohc_session_status_t;


typedef bool (*iprohc_session_start_t) (struct iprohc_session *const session)
	__attribute__((warn_unused_result, nonnull(1)));

typedef bool (*iprohc_session_handler_t) (struct iprohc_session *const session,
                                          const uint8_t *const msg,
                                          const size_t len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

typedef bool (*iprohc_session_stop_t) (struct iprohc_session *const session)
	__attribute__((warn_unused_result, nonnull(1)));


/** The generic part of the session shared by server and client */
struct iprohc_session
{
	int tcp_socket;                    /**< The TCP socket for the control channel */
	gnutls_session_t tls_session;      /**< The TLS session for the control channel */
	struct in_addr local_address;      /**< The local address on the TUN interface */

	struct in_addr dst_addr;             /**< The IP address of the remote endpoint */
	char dst_addr_str[INET_ADDRSTRLEN];  /**< string representation of dst_addr */
	struct in_addr src_addr;             /**< The IP address of the local endpoint */

	/** The handler for starting the control session */
	iprohc_session_start_t start_ctrl;
	/** The handler for received control messages */
	iprohc_session_handler_t handle_ctrl_msg;
	/** The handler for stopping the control session */
	iprohc_session_start_t stop_ctrl;
	/** The private data to give to the control message handler */
	void *handle_ctrl_opaque;

	struct iprohc_tunnel tunnel;   /**< The tunnel context */

	int p2c[2];                      /**< The communication pipe between parent
	                                      and child threads */
	pthread_t thread_tunnel;         /**< The thread that handle the session */
	pthread_attr_t thread_attr;      /**< The attributes for the thread */
	void *thread_stack;              /**< The stack for the thread */
	volatile AO_t is_thread_running; /**< Whether the thread is running or not */

	iprohc_session_status_t status;  /**< The session status */

	struct timeval last_activity;  /**< The time at which last control message
	                                    was received */
	int keepalive_timer_fd;        /**< The timer to send keepalive messages in
	                                    case of inactivity on control channel */
};


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
	__attribute__((warn_unused_result, nonnull(1)));

bool iprohc_session_free(struct iprohc_session *const session)
	__attribute__((warn_unused_result, nonnull(1)));

bool iprohc_session_update_keepalive(struct iprohc_session *const session,
                                     const size_t timeout)
	__attribute__((warn_unused_result, nonnull(1)));

bool iprohc_session_start(struct iprohc_session *const session)
	__attribute__((warn_unused_result, nonnull(1)));

bool iprohc_session_stop(struct iprohc_session *const session)
	__attribute__((warn_unused_result, nonnull(1)));

#endif

