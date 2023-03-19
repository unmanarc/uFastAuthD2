#ifndef LOGINAUTHMETHODS_H
#define LOGINAUTHMETHODS_H

#include <Mantids29/Auth/manager.h>
#include <Mantids29/RPC_Fast/fastrpc.h>
#include <json/json.h>

namespace Mantids29 { namespace RPC { namespace Templates {

// This template is for FastRPC
class LoginAuth
{
public:
    /**
     * @brief AddLoginAuthMethods Add selected/reduced/filtered set of login authentication methods as server functions to the fastrpc connection for remote web applications
     * @param auth authentication manager (with full access to the authentication interface)
     * @param fastRPC RPC engine to expose the methods
     */
    static void AddLoginAuthMethods(Mantids29::Authentication::Manager * auth,  Mantids29::RPC::Fast::FastRPC * fastRPC);

private:
    static json isAccountDisabled(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json isAccountConfirmed(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);

    static json accountAttribs(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountGivenName(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountLastName(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountDescription(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountEmail(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountExtraData(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);

    static json applicationDescription(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json applicationValidateOwner(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json applicationValidateAccount(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json applicationOwners(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json applicationAccounts(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);

    static json accountSecretPublicData(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json passIndexesRequiredForLogin(void * obj, const std::string &, const json &, void*, const std::string &);
    static json passIndexesUsedByAccount(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json passIndexDescription(void * obj, const std::string &, const json & payload, void*, const std::string &);
    static json passIndexLoginRequired(void * obj, const std::string &, const json & payload, void*, const std::string &);
    static json accountExpirationDate(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);

    static json authenticate(void * obj, const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountChangeAuthenticatedSecret(void * obj,const std::string &connectionKey, const json & payload, void*, const std::string &);
    static json accountAdd(void * obj,const std::string &connectionKey,  const json & payload, void*, const std::string &);
    static json attribExist(void * obj,const std::string &connectionKey,  const json & payload, void*, const std::string &);
    static json attribAdd(void *obj,const std::string &connectionKey, const json &payload, void*, const std::string &);
    static json attribRemove(void *obj,const std::string &connectionKey, const json &payload, void*, const std::string &);
    static json attribChangeDescription(void *obj,const std::string &connectionKey, const json &payload, void*, const std::string &);
    static json attribDescription(void *obj,const std::string &connectionKey, const json &payload, void*, const std::string &);
    static json getAccountAllSecretsPublicData(void * obj,const std::string &connectionKey,  const json & payload, void*, const std::string &);
    static json isAccountSuperUser(void * obj,const std::string &connectionKey,  const json & payload, void*, const std::string &);
    static json accountValidateAttribute(void * obj,const std::string &connectionKey,  const json & payload, void*, const std::string &);
    static json getStaticContent(void *, const std::string &, const json &, void*, const std::string &);
    static std::string getAppNameFromConnectionKey(const std::string &connectionKey);

};

}}}
#endif // LOGINAUTHMETHODS_H
