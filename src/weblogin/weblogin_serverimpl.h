#pragma once

#include <json/json.h>
#include <Mantids30/Sessions/session.h>
#include <Mantids30/Net_Sockets/socket_stream_base.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebLogin_ServerImpl
{
public:
    WebLogin_ServerImpl() = default;

    static bool createService();

private:
    static bool handleProtocolInitializationFailure(void *webServer, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream_Base> sock);
    static bool handleClientAcceptTimeoutOccurred(void *webServer, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream_Base> sock);
};


