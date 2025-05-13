#pragma once

#include <Mantids30/Protocol_FastRPC1/fastrpc.h>


class LoginAuthProxyMethods
{
public:
    LoginAuthProxyMethods() = default;
    static void AddLoginAuthProxyMethods(Mantids30::Network::Protocols::FastRPC::FastRPC1 * fastRPC);
private:
    static json proxy(std::shared_ptr<void> context, const std::string &key, const json & parameters, std::shared_ptr<void> cntObj, const std::string & cntData);

};
