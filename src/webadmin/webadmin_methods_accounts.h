#pragma once

#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

class WebAdminMethods_Accounts
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;

protected:
    static void addMethods_Accounts(std::shared_ptr<MethodsHandler> methods);

    static void addAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void doesAccountExist(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void removeAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void disableAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void confirmAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void updateAccountInfo(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
/*    static void changeAccountDescription(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeAccoungGivenName(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeAccountLastName(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeAccountEmail(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeAccountExtraData(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);*/
    static void changeAccountExpiration(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void updateAccountRoles(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountFlags(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountInfo(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountDetails(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountLastLogin(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void resetBadAttemptsOnCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountExpirationTime(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void isAccountExpired(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void validateAccountApplicationPermission(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountBlockToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void blockAccountUsingToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void listAccounts(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void searchAccounts(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountRoles(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountDirectApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void getAccountUsableApplicationPermissions(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);

private:
    static std::map<std::string, std::string> jsonToMap(const json &jValue);
};

