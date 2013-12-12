/*
This file is part of iprohc.

iprohc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

iprohc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef IPROHC_SERVER_SERVER_CONFIG_H
#define IPROHC_SERVER_SERVER_CONFIG_H

#include "server.h"

bool iprohc_server_load_config(const char *const conf_file,
                               struct server_opts *const server_opts)
	__attribute__((warn_unused_result, nonnull(1, 2)));

#endif

