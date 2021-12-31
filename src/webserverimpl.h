#ifndef WEBSERVERIMPL_H
#define WEBSERVERIMPL_H

#include <json/json.h>
#include <mdz_auth/manager.h>
#include <mdz_auth/session.h>
#include <mdz_net_sockets/streamsocket.h>

namespace AUTHSERVER { namespace WEB {

class WebServerImpl
{
public:
    WebServerImpl();
    static bool createWebServer();

private:
    static bool protoInitFail(void *webServer, Mantids::Network::Streams::StreamSocket *sock, const char *remoteIP, bool isSecure);
/*
    static json statMethods(void *, Mantids::Authentication::Manager *, Mantids::Authentication::Session *, const json &);
    static json controlMethods(void *, Mantids::Authentication::Manager *, Mantids::Authentication::Session *, const json &);*/
};

}}

#endif // WEBSERVERIMPL_H
