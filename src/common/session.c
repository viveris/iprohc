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


/**
 * @brief Initialize the given generic session
 *
 * @param session         The session to initialize
 * @param tls_type        The type of TLS endpoint: GNUTLS_CLIENT or GNUTLS_SERVER
 * @param tls_cred        The credentials to use for the TLS session
 * @param priority_cache  The TLS priority cache
 * @param ctrl_socket     The TCP socket used for the control channel
 * @param local_addr      The IP address of the local endpoint
 * @param remote_addr     The IP address of the remote endpoint
 * @param raw_socket      The RAW socket to use to send packets to remote endpoint
 * @param tun_fd          The file descriptor of the local TUN interface
 * @param base_dev_mtu    The MTU of the base device used to send packets to the
 *                        remote endpoint
 * @param tun_dev_mtu     The MTU of the local TUN interface
 * @return                true if session was successfully initialized,
 *                        false if a problem occurred
 */
bool iprohc_session_new(struct iprohc_session *const session,
                        const gnutls_connection_end_t tls_type,
                        gnutls_certificate_credentials_t tls_cred,
                        gnutls_priority_t priority_cache,
                        const int ctrl_socket,
                        const struct in_addr local_addr,
                        const struct sockaddr_in remote_addr,
                        const int raw_socket,
                        const int tun_fd,
                        const size_t base_dev_mtu,
                        const size_t tun_dev_mtu)
{
	int ret;

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
	session->local_address = local_addr;
	session->src_addr.s_addr = INADDR_ANY;
	session->dst_addr = remote_addr.sin_addr;
	session->status = IPROHC_SESSION_CONNECTING;
	session->last_keepalive.tv_sec = -1;

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

	/* create locks */
	ret = pthread_mutex_init(&(session->status_lock), NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[client %s] failed to init lock: %s (%d)",
		      session->dst_addr_str, strerror(ret), ret);
		goto tls_deinit;
	}
	ret = pthread_mutex_init(&(session->client_lock), NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[client %s] failed to init client_lock: %s (%d)",
		      session->dst_addr_str, strerror(ret), ret);
		goto destroy_lock;
	}

	/* init tunnel context */
	if(!iprohc_tunnel_new(&(session->tunnel), raw_socket, tun_fd,
	                      base_dev_mtu, tun_dev_mtu))
	{
		trace(LOG_ERR, "[client %s] failed to init tunnel context",
		      session->dst_addr_str);
		goto destroy_client_lock;
	}

	return true;

destroy_client_lock:
	pthread_mutex_destroy(&(session->client_lock));
destroy_lock:
	pthread_mutex_destroy(&(session->status_lock));
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
	/* destroy locks */
	pthread_mutex_destroy(&session->client_lock);
	pthread_mutex_destroy(&session->status_lock);

	/* free TLS resources */
	gnutls_deinit(session->tls_session);

	/* reset tunnel context */
	if(!iprohc_tunnel_free(&(session->tunnel)))
	{
		trace(LOG_ERR, "[client %s] failed to reset tunnel context",
		      session->dst_addr_str);
	}

	/* reset source and destination addresses */
	memset(&(session->dst_addr), 0, sizeof(struct in_addr));
	memset(&(session->dst_addr_str), 0, INET_ADDRSTRLEN);
	memset(&(session->src_addr), 0, sizeof(struct in_addr));

	/* close TCP socket */
	close(session->tcp_socket);
	session->tcp_socket = -1;

	return true;
}

