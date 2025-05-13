#pragma once

#include <json/json.h>
#include <Mantids30/Sessions/session.h>
#include <Mantids30/Net_Sockets/socket_stream.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebLogin_ServerImpl
{
public:
    WebLogin_ServerImpl() = default;

    static bool createService();

};


