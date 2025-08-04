#ifndef TOKENSMANAGER_H
#define TOKENSMANAGER_H


#include "IdentityManager/ds_application.h"

#include <Mantids30/Helpers/json.h>
#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/Protocol_HTTP/api_return.h>

class TokensManager
{
public:
    TokensManager() = default;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using HTTPv1_Base = Mantids30::Network::Protocols::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;


    static void configureAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const std::string &refreshTokenId, const std::string &jwtAccountName,
                                     const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds);

    static void configureRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const std::string &refreshTokenId, const std::string &jwtAccountName,
                                      const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds);

    static void setIAMAccessToken(APIReturn &response, const RequestParameters &request, const Mantids30::DataFormat::JWT::Token &intermediateToken,
                                  const Mantids30::DataFormat::JWT::Token &currentAccessToken, bool keepAuthenticated, const time_t &currentIntermediateTokenExpirationTime);


};

#endif // TOKENSMANAGER_H
