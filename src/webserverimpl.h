#ifndef WEBSERVERIMPL_H
#define WEBSERVERIMPL_H

#include <json/json.h>
#include <Mantids29/Auth/manager.h>
#include <Mantids29/Auth/session.h>
#include <Mantids29/Net_Sockets/socket_stream_base.h>

namespace AUTHSERVER { namespace WEB {

class WebServerImpl
{
public:
    WebServerImpl();
    //static bool createWebServer();
    static bool createWebService();

private:
    static bool protoInitFail(void *webServer, Mantids29::Network::Sockets::Socket_Stream_Base *sock, const char *remoteIP, bool isSecure);
};

}}

#endif // WEBSERVERIMPL_H
