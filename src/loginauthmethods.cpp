#include "loginauthmethods.h"

#include <mdz_prg_logs/applog.h>

#include "defs.h"
#include "globals.h"

#include <boost/algorithm/string.hpp>

using namespace AUTHSERVER;
using namespace Mantids::Application;
using namespace Mantids::RPC;
using namespace Mantids;

/**
 * @brief readFile2String Local function to convert a file to a std::string (with every line), very useful for web resources.
 * @param fileName required filepath
 * @return string with the file content, or empty if the file was not found.
 */
std::string readFile2String(const std::string &fileName)
{
    std::ifstream inputFileStream(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

    std::ifstream::pos_type iFileSize = inputFileStream.tellg();
    inputFileStream.seekg(0, std::ios::beg);

    std::vector<char> bytes(iFileSize);
    inputFileStream.read(bytes.data(), iFileSize);

    return std::string(bytes.data(), iFileSize);
}


void Mantids::RPC::Templates::LoginAuth::AddLoginAuthMethods(Mantids::Authentication::Manager *auth, Mantids::RPC::Fast::FastRPC *fastRPC)
{
    // AUTHENTICATION FUNCTIONS:
    fastRPC->addMethod("authenticate",{&authenticate,auth});

    // ACCOUNT SECRET MANIPULATION FUNCTIONS:
    fastRPC->addMethod("accountChangeAuthenticatedSecret",{&accountChangeAuthenticatedSecret,auth});
    fastRPC->addMethod("getAccountAllSecretsPublicData",{&getAccountAllSecretsPublicData,auth});
    fastRPC->addMethod("accountSecretPublicData",{&accountSecretPublicData,auth});

    // ACCOUNT PASSWORD @INDEX  FUNCTIONS:
    fastRPC->addMethod("passIndexDescription",{&passIndexDescription,auth});
    fastRPC->addMethod("passIndexesRequiredForLogin",{&passIndexesRequiredForLogin,auth});
    fastRPC->addMethod("passIndexesUsedByAccount",{&passIndexesUsedByAccount,auth});
    fastRPC->addMethod("passIndexLoginRequired",{&passIndexLoginRequired,auth});

    // ACCOUNT ATTRIBUTE FUNCTIONS:
    fastRPC->addMethod("accountAttribs",{&accountAttribs,auth});
    fastRPC->addMethod("accountGivenName",{&accountGivenName,auth});
    fastRPC->addMethod("accountLastName",{&accountLastName,auth});
    fastRPC->addMethod("accountDescription",{&accountDescription,auth});
    fastRPC->addMethod("accountEmail",{&accountEmail,auth});
    fastRPC->addMethod("accountExtraData",{&accountExtraData,auth});

    // APPLICATION FUNCTIONS
    fastRPC->addMethod("applicationDescription",{&applicationDescription,auth});
    fastRPC->addMethod("applicationValidateOwner",{&applicationValidateOwner,auth});
    fastRPC->addMethod("applicationValidateAccount",{&applicationValidateAccount,auth});
    fastRPC->addMethod("applicationOwners",{&applicationOwners,auth});
    fastRPC->addMethod("applicationAccounts",{&applicationAccounts,auth});

    // ACCOUNT ATTRIBUTE FUNCTIONS:
    fastRPC->addMethod("attribExist",{&attribExist,auth});
    fastRPC->addMethod("attribAdd",{&attribAdd,auth});
    fastRPC->addMethod("attribRemove",{&attribRemove,auth});
    fastRPC->addMethod("attribChangeDescription",{&attribChangeDescription,auth});
    fastRPC->addMethod("attribDescription",{&attribDescription,auth});
    fastRPC->addMethod("isAccountSuperUser",{&isAccountSuperUser,auth});
    fastRPC->addMethod("isAccountDisabled",{&isAccountDisabled,auth});
    fastRPC->addMethod("isAccountConfirmed",{&isAccountConfirmed,auth});

    // ACCOUNT VALIDATION FUNCTIONS:
    fastRPC->addMethod("accountExpirationDate",{&accountExpirationDate,auth});
    fastRPC->addMethod("accountValidateAttribute",{&accountValidateAttribute,auth});

    //    fastRPC->addMethod("accountAdd",{&accountAdd,auth});

    // PROVIDED STATIC CONTENT FUNCTIONS:
    fastRPC->addMethod("getStaticContent",{&getStaticContent,auth});

}

json Templates::LoginAuth::isAccountDisabled(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( !auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
        payloadOut["retCode"] = true;
    else
        payloadOut["retCode"] = auth->isAccountDisabled( JSON_ASSTRING(payload,"accountName","") );

    return payloadOut;
}

json Templates::LoginAuth::isAccountConfirmed(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( !auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
        payloadOut["retCode"] = false;
    else
        payloadOut["retCode"] = auth->isAccountConfirmed( JSON_ASSTRING(payload,"accountName","") );

    return payloadOut;
}

json Templates::LoginAuth::accountAttribs(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        auto i = auth->accountAttribs( JSON_ASSTRING(payload,"accountName","") );

        payloadOut["confirmed"] = i.confirmed;
        payloadOut["enabled"] = i.enabled;
        payloadOut["superuser"] = i.superuser;
    }

    return payloadOut;
}

json Templates::LoginAuth::accountGivenName(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut["givenName"] = auth->accountGivenName( JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::accountLastName(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut["lastName"] = auth->accountLastName( JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::accountDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut["description"] = auth->accountDescription(JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::accountEmail(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut["email"] = auth->accountEmail(JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::accountExtraData(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut["extraData"] = auth->accountExtraData(JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::applicationDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if (  getAppNameFromConnectionKey(connectionKey) == JSON_ASSTRING(payload,"applicationName","") )
    {
        payloadOut["description"] = auth->applicationDescription( JSON_ASSTRING(payload,"applicationName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::applicationValidateOwner(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if (  getAppNameFromConnectionKey(connectionKey) == JSON_ASSTRING(payload,"applicationName","") )
    {
        payloadOut["retCode"] = auth->applicationValidateOwner( JSON_ASSTRING(payload,"applicationName",""),  JSON_ASSTRING(payload,"accountName",""));
    }

    return payloadOut;
}

json Templates::LoginAuth::applicationValidateAccount(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    if (  getAppNameFromConnectionKey(connectionKey) == JSON_ASSTRING(payload,"applicationName","") )
    {
        payloadOut["retCode"] = auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") );
    }

    return payloadOut;
}

json Templates::LoginAuth::applicationOwners(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    if (  getAppNameFromConnectionKey(connectionKey) == JSON_ASSTRING(payload,"applicationName","") )
    {
        int i = 0;
        for ( auto & owner : auth->applicationOwners(getAppNameFromConnectionKey(connectionKey)))
        {
            payloadOut[i] = owner;
            i++;
        }
    }

    return payloadOut;
}

json Templates::LoginAuth::applicationAccounts(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    if (  getAppNameFromConnectionKey(connectionKey) == JSON_ASSTRING(payload,"applicationName","") )
    {
        int i = 0;
        for ( auto & account : auth->applicationAccounts(getAppNameFromConnectionKey(connectionKey)))
        {
            payloadOut[i] = account;
            i++;
        }
    }

    return payloadOut;
}

json Templates::LoginAuth::accountSecretPublicData(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        auto v = auth->accountSecretPublicData(JSON_ASSTRING(payload,"accountName",""),JSON_ASUINT(payload,"passIndex",0) );

        for (const auto &i : v.getMap())
        {
            payloadOut[i.first] = i.second;
        }
    }
    return payloadOut;
}

json Templates::LoginAuth::passIndexesRequiredForLogin(void *obj, const std::string &, const json &)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    uint32_t x=0;
    for (auto i : auth->passIndexesRequiredForLogin())
    {
        payloadOut[x++] = i;
    }
    return payloadOut;
}

json Templates::LoginAuth::passIndexesUsedByAccount(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    uint32_t x=0;

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        for (auto i : auth->passIndexesUsedByAccount(JSON_ASSTRING(payload,"accountName","")))
        {
            payloadOut[x++] = i;
        }
    }
    return payloadOut;
}

json Templates::LoginAuth::passIndexDescription(void *obj, const std::string &, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut = auth->passIndexDescription(JSON_ASUINT(payload,"passIndex",0));
    return payloadOut;
}

json Templates::LoginAuth::passIndexLoginRequired(void *obj, const std::string &, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut = auth->passIndexLoginRequired(JSON_ASUINT(payload,"passIndex",0));
    return payloadOut;
}

json Templates::LoginAuth::accountExpirationDate(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut = 0;
    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut = (Json::Int64)auth->accountExpirationDate(JSON_ASSTRING(payload,"accountName",""));
    }
    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::authenticate(void * obj, const std::string & connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    Mantids::Authentication::sClientDetails clientDetails;
    clientDetails.sIPAddr = JSON_ASSTRING(payload["clientDetails"],"ipAddr","");
    clientDetails.sExtraData = JSON_ASSTRING(payload["clientDetails"],"extraData","");
    clientDetails.sTLSCommonName = JSON_ASSTRING(payload["clientDetails"],"tlsCN","");
    clientDetails.sUserAgent = JSON_ASSTRING(payload["clientDetails"],"userAgent","");

    std::map<uint32_t, std::string> accountPassIndexesUsedForLogin;

    payloadOut["retCode"] = (uint32_t) auth->authenticate(   getAppNameFromConnectionKey(connectionKey),
                                                             clientDetails,
                                                             JSON_ASSTRING(payload,"accountName",""),
            JSON_ASSTRING(payload,"password",""),
            JSON_ASUINT(payload,"passIndex",0),
            Mantids::Authentication::getAuthModeFromString(JSON_ASSTRING(payload,"authMode","")),
            JSON_ASSTRING(payload,"challengeSalt",""),
            &accountPassIndexesUsedForLogin  );

    int i=0;
    for (const auto & v : accountPassIndexesUsedForLogin)
    {
        payloadOut["accountPassIndexesUsedForLogin"][i]["idx"] = v.first;
        payloadOut["accountPassIndexesUsedForLogin"][i]["txt"] = v.second;
        i++;
    }



    Globals::getAppLog()->log2(__func__,JSON_ASSTRING(payload,"accountName",""),clientDetails.sIPAddr,
            JSON_ASUINT(payloadOut,"retCode",0)? Logs::LEVEL_WARN : Logs::LEVEL_INFO
                                            , "Account Authentication Result: %lu - %s, for application %s", JSON_ASUINT(payloadOut,"retCode",0),Mantids::Authentication::getReasonText((Mantids::Authentication::Reason)JSON_ASUINT(payloadOut,"retCode",0)),getAppNameFromConnectionKey(connectionKey).c_str() );


    payloadOut["retMessage"] = Mantids::Authentication::getReasonText((Mantids::Authentication::Reason)JSON_ASUINT(payloadOut,"retCode",0));

    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::accountChangeAuthenticatedSecret(void * obj,const std::string & connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;

    json payloadOut;

    std::map<std::string,std::string> mNewSecret;
    for ( const auto & member : payload["newSecret"].getMemberNames() )
    {
        mNewSecret[member] = JSON_ASSTRING(payload["newSecret"],member,"");
    }

    Mantids::Authentication::Secret newSecret;
    newSecret.fromMap(mNewSecret);

    Mantids::Authentication::sClientDetails clientDetails;
    clientDetails.sIPAddr = JSON_ASSTRING(payload["clientDetails"],"ipAddr","");
    clientDetails.sExtraData = JSON_ASSTRING(payload["clientDetails"],"extraData","");
    clientDetails.sTLSCommonName = JSON_ASSTRING(payload["clientDetails"],"tlsCN","");
    clientDetails.sUserAgent = JSON_ASSTRING(payload["clientDetails"],"userAgent","");

    payloadOut["retCode"] = auth->accountChangeAuthenticatedSecret( getAppNameFromConnectionKey(connectionKey),
                                                                    payload["accountName" ].asString(),
                                                                    JSON_ASUINT(payload,"passIndex",0),
                                                                    JSON_ASSTRING(payload,"currentPassword",""),
                                                                    newSecret,
                                                                    clientDetails,
                                                                    Mantids::Authentication::getAuthModeFromString(JSON_ASSTRING(payload,"authMode","")),
                                                                    JSON_ASSTRING(payload,"challengeSalt","")
                                                                  );


    Globals::getAppLog()->log2(__func__,JSON_ASSTRING(payload,"accountName",""),clientDetails.sIPAddr,
            JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                            , "Account Change Authentication Result: %lu", JSON_ASBOOL(payloadOut,"retCode",false)?1:0);


    return payloadOut;

}

json Mantids::RPC::Templates::LoginAuth::accountAdd(void * obj,const std::string & connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;

    json payloadOut;

    std::map<std::string,std::string> mNewSecret;
    for ( const auto & member : payload["newSecret"].getMemberNames() )
    {
        mNewSecret[member] = JSON_ASSTRING(payload,member,"");
    }

    Mantids::Authentication::Secret newSecret;
    newSecret.fromMap(mNewSecret);

    Mantids::Authentication::sAccountDetails accountDetails;
    accountDetails.sDescription = JSON_ASSTRING(payload["accountDetails"],"description","");
    accountDetails.sEmail = JSON_ASSTRING(payload["accountDetails"],"email","");
    accountDetails.sExtraData = JSON_ASSTRING(payload["accountDetails"],"extraData","");
    accountDetails.sGivenName = JSON_ASSTRING(payload["accountDetails"],"givenName","");
    accountDetails.sLastName = JSON_ASSTRING(payload["accountDetails"],"lastName","");
    Mantids::Authentication::sAccountAttribs accountAttribs;
    accountAttribs.confirmed = true;
    accountAttribs.enabled = false;
    accountAttribs.superuser = false;

    // TODO: add to the application.

    payloadOut["retCode"] =
            auth->accountAdd(   JSON_ASSTRING(payload,"accountName",""),
            newSecret,
            accountDetails,
            JSON_ASUINT64(payload,"expiration",0),
            accountAttribs); // Superuser
    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::attribExist(void *obj,const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;

    // This function is important to aplications to understand if they have been installed into the user manager
    json payloadOut;
    payloadOut["retCode"] = auth->attribExist( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") } );
    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::attribAdd(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribAdd( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") },
                                             JSON_ASSTRING(payload,"attribDescription","")
            );


    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Adding Attribute '%s' to Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);

    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::attribRemove(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribRemove( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") });

    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Removing Attribute '%s' from Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);

    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::attribChangeDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribChangeDescription( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") },
                                                           JSON_ASSTRING(payload,"attribDescription","")
            );


    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Changing description to Attribute '%s' from Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);


    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::attribDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["attribDescription"] = auth->attribDescription( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") } );
    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::getAccountAllSecretsPublicData(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        for (const auto & i : auth->getAccountAllSecretsPublicData( JSON_ASSTRING(payload,"accountName","") ))
        {
            for (const auto & j :i.second.getMap())
            {
                payloadOut[std::to_string(i.first)][j.first] = j.second;
            }
        }
        return payloadOut;
    }
    else
    {
        return payloadOut;
    }
}

json Mantids::RPC::Templates::LoginAuth::isAccountSuperUser(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( !auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
        payloadOut["retCode"] = false;
    else
        payloadOut["retCode"] = auth->isAccountSuperUser( JSON_ASSTRING(payload,"accountName","") );

    return payloadOut;
}

json Mantids::RPC::Templates::LoginAuth::accountValidateAttribute(void *obj, const std::string &connectionKey, const json &payload)
{
    Mantids::Authentication::Manager * auth = (Mantids::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->accountValidateAttribute( JSON_ASSTRING(payload,"accountName",""), { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") } );
    return payloadOut;
}

json Templates::LoginAuth::getStaticContent(void *, const std::string &, const json &)
{
    json staticContents;
    // Now here we send/init everything...
    std::string resourcesPath = Globals::getConfig_main()->get<std::string>("WebServer.ResourcesPath",AUTHSERVER_WEBDIR);

    int i=0;

    // Push static content required for login operations

    std::list<std::string> assets
            = {
                    // Mantids:
                    "/secrets.html"
                    "/assets/js/mantids_login.js",
                    "/assets/js/mantids_main.js",
                    "/assets/js/mantids_passwd.js",
                    "/assets/js/mantids_validations.js",
                    "/assets/css/login.css",
                    "/assets/css/progress.css",
                    "/assets/css/select.css",
                    "/assets/css/sticky-footer.css",

                    // JQuery:
                    "/assets/js/jquery-3.6.0.min.js",

                    // Bootstrap:
                    "/assets/js/bootstrap.min.js",
                    "/assets/css/bootstrap-grid.min.css",
                    "/assets/css/bootstrap-reboot.min.css.map",
                    "/assets/css/bootstrap-grid.min.css.map",
                    "/assets/css/bootstrap-reboot.min.css",
                    "/assets/css/bootstrap.min.css",
                    "/assets/css/bootstrap.min.css.map",
                    "/assets/js/bootstrap.min.js.map",
                    "/assets/js/bootstrap.bundle.min.js.map",
                    "/assets/js/bootstrap.min.js",
                    "/assets/js/bootstrap.bundle.min.js",
              };

    for (const auto & asset : assets)
    {
        staticContents[i]["content"] = readFile2String(resourcesPath + asset);
        staticContents[i++]["path"] = asset;
    }


    return staticContents;
}

std::string Mantids::RPC::Templates::LoginAuth::getAppNameFromConnectionKey(const std::string &connectionKey)
{
    std::vector<std::string> splstr;
    split(splstr,connectionKey,boost::is_any_of("."),boost::token_compress_on);
    if (splstr.size())
        return splstr[0];
    return "";
}

