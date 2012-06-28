/* config.c -- Parse config file

Config file is in (very) basic yaml format :
general:
	port: xxx
	pidfile: xxx
	p12: xxx

tunnel:
	packing: xxx
	maxcid: xxx

Only general and rohc are allowed, all the others are ignored, with a warning.
The parser is deliberately simple for this use case so it :
 - limit the indentation to maximum 2
 - forbids sequence

*/

#include <yaml.h>
#include <arpa/inet.h>


#include "log.h"
#include "server.h"

#define MAX_LEVEL 3

enum parse_state
{
	WAIT_NODE1,
	WAIT_NODE2
} ;

int handle_line(char* section, char* key, char* value, struct server_opts* server_opts)
{
	trace(LOG_DEBUG, "Conf [%s] %s => %s", section, key, value) ;
	/* Section general */
	if (strcmp(section, "general") == 0) {
		if (strcmp(key, "port") == 0) {
			server_opts->port = atoi(value) ;
			return 0 ;
		}
		if (strcmp(key, "pidfile") == 0) {
			strncpy(server_opts->pidfile_path, value, 1024) ;
			return 0;
		}
		if (strcmp(key, "p12file") == 0) {
			strncpy(server_opts->pkcs12_f, value, 1024) ;
			return 0;
		}
	}

	if (strcmp(section, "tunnel") == 0) {
		if (strcmp(key, "ipaddr") == 0) {
			server_opts->local_address = inet_addr(value) ;
			return 0;
		}
		if (strcmp(key, "packing") == 0) {
			server_opts->params.packing = atoi(value) ;
			return 0;
		}
		if (strcmp(key, "maxcid") == 0) {
			server_opts->params.max_cid = atoi(value) ;
			return 0;
		}
		if (strcmp(key, "unidirectional") == 0) {
			server_opts->params.is_unidirectional = atoi(value) ;
			return 0;
		}
		if (strcmp(key, "keepalive") == 0) {
			server_opts->params.keepalive_timeout = atoi(value) ;
			return 0;
		}
	}

	return 1 ;
}

int parse_config(const char* path, struct server_opts* server_opts)
{
	yaml_parser_t parser;
	yaml_event_t event;

	yaml_parser_initialize(&parser);

	FILE* input = fopen(path, "rb");
	yaml_parser_set_input_file(&parser, input);
	
	int level = 0;
	enum parse_state states[MAX_LEVEL] ;

	char section[1024] ;
	char key[1024] ;
	char value[1024] ;

	int done = 0 ;
	while (!done) {
	    if (!yaml_parser_parse(&parser, &event))
	        goto error;

	    switch (event.type) {

	    	case YAML_MAPPING_START_EVENT :
				level++ ;
				if (level >= MAX_LEVEL) {
					trace(LOG_ERR, "Too much level of ident") ;
					goto error;
				}
				states[level] = WAIT_NODE1 ;
				break ;
			
			case YAML_MAPPING_END_EVENT :
				level--;
				states[level] = WAIT_NODE1 ;
				break ;

			case YAML_SCALAR_EVENT :
				switch (states[level]) {
					case WAIT_NODE1:
						if (level == 1) {
							strncpy(section, (char*) event.data.scalar.value, event.data.scalar.length+1) ;
						} else if (level == 2) {
							strncpy(key, (char*) event.data.scalar.value, event.data.scalar.length+1) ;
						}
						states[level] = WAIT_NODE2 ;
						break ;
					case WAIT_NODE2:
						if (level == 2)  {
							strncpy(value, (char*) event.data.scalar.value, event.data.scalar.length +1) ;
							handle_line(section, key, value, server_opts) ;
							states[level] = WAIT_NODE1 ;
						}
						break ;
				}
				break ;

	    	case YAML_SEQUENCE_START_EVENT :
	    	case YAML_SEQUENCE_END_EVENT :
				trace(LOG_WARNING, "Unexpected sequence in iprohc config file") ;
				break ;
			case YAML_ALIAS_EVENT :
				trace(LOG_WARNING, "Unexpected alias in iprohc config file") ;
				break;
			default:
				break ;
		}

	    done = (event.type == YAML_STREAM_END_EVENT);
	    yaml_event_delete(&event);
	}

	yaml_parser_delete(&parser);
	fclose(input) ;

	return 0 ;

error:
	yaml_parser_delete(&parser);
	return -1 ;
}

