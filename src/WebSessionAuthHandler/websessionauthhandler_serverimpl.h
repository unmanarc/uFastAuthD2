#pragma once

#include <Mantids30/Net_Sockets/socket_stream.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Sessions/session.h>
#include <json/json.h>

class WebSessionAuthHandler_ServerImpl
{
public:
    WebSessionAuthHandler_ServerImpl() = default;

    static bool createService();
};
