#ifndef LOGINAUTHMETHODS_H
#define LOGINAUTHMETHODS_H

#include <cx2_auth/manager.h>
#include <cx2_xrpc_fast/fastrpc.h>
#include <json/json.h>

namespace CX2 { namespace RPC { namespace Templates {

// This template is for FastRPC
class LoginAuth
{
public:
    static void AddLoginAuthMethods(CX2::Authentication::Manager * auth,  CX2::RPC::Fast::FastRPC * fastRPC);

private:
    static json accountSecretPublicData(void * obj, const std::string &key, const json & payload);
    static json passIndexesRequiredForLogin(void * obj, const std::string &, const json &);
    static json passIndexesUsedByAccount(void * obj, const std::string &connectionKey, const json & payload);
    static json passIndexDescription(void * obj, const std::string &, const json & payload);
    static json passIndexLoginRequired(void * obj, const std::string &, const json & payload);
    static json accountExpirationDate(void * obj, const std::string &connectionKey, const json & payload);

    static json authenticate(void * obj, const std::string &key, const json & payload);
    static json accountChangeAuthenticatedSecret(void * obj,const std::string & key, const json & payload);
    static json accountAdd(void * obj,const std::string & key,  const json & payload);
    static json attribExist(void * obj,const std::string & key,  const json & payload);
    static json attribAdd(void *obj,const std::string &connectionKey, const json &payload);
    static json attribRemove(void *obj,const std::string &connectionKey, const json &payload);
    static json attribChangeDescription(void *obj,const std::string &connectionKey, const json &payload);
    static json attribDescription(void *obj,const std::string &connectionKey, const json &payload);
    static json getAccountAllSecretsPublicData(void * obj,const std::string & key,  const json & payload);
    static json isAccountSuperUser(void * obj,const std::string & key,  const json & payload);
    static json accountValidateAttribute(void * obj,const std::string & key,  const json & payload);
    static json getStaticContent(void *, const std::string &, const json &);
    static std::string getAppNameFromConnectionKey(const std::string & key);

};

}}}
#endif // LOGINAUTHMETHODS_H
