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
 * @file   client_session.h
 * @brief  The context of the session at client
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef IPROHC_CLIENT_SESSION__H
#define IPROHC_CLIENT_SESSION__H

#include "session.h"

#include <net/if.h>

/** The context of the session at client */
struct iprohc_client_session
{
	struct iprohc_session session; /**< The generic session context */

	char tun_name[IFNAMSIZ];       /**< The name of the TUN interface */
	char basedev[IFNAMSIZ];        /**< The name of the base interface */
	char *up_script_path;          /**< The path to the UP script */
	int packing;                   /**< The packing level that client wishes to enforce */
};

#endif

