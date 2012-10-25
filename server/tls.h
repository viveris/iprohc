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


#include <gnutls/gnutls.h>

int generate_dh_params (gnutls_dh_params_t* dh_params) ;
int load_p12(gnutls_certificate_credentials_t xcred, char* p12_file, char* password) ;
void gnutls_transport_set_ptr_nowarn(gnutls_session_t session, int ptr) ;
