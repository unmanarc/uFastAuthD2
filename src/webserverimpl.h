#ifndef WEBSERVERIMPL_H
#define WEBSERVERIMPL_H

#include <json/json.h>
#include <mdz_auth/manager.h>
#include <mdz_auth/session.h>
#include <mdz_net_sockets/socket_streambase.h>

namespace AUTHSERVER { namespace WEB {

class WebServerImpl
{
public:
    WebServerImpl();
    static bool createWebServer();
    static bool createWebService();

private:
    static bool protoInitFail(void *webServer, Mantids::Network::Sockets::Socket_StreamBase *sock, const char *remoteIP, bool isSecure);
};

}}

#endif // WEBSERVERIMPL_H
