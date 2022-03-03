
set(OPTION_DEFAULT ON)
set(OPTION_CLIENT_DEFAULT OFF)
set(OPTION_SERVER_DEFAULT ON)

define_channel_options(NAME "bubcli" TYPE "static"
	DESCRIPTION "Bubble client information passing channel"
	SPECIFICATIONS "[NONE]"
	DEFAULT ${OPTION_DEFAULT})

#define_channel_client_options(${OPTION_CLIENT_DEFAULT})
define_channel_server_options(${OPTION_SERVER_DEFAULT})

