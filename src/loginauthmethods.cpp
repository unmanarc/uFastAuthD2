#include "loginauthmethods.h"

#include <cx2_prg_logs/applog.h>

#include "defs.h"
#include "globals.h"

#include <boost/algorithm/string.hpp>

using namespace AUTHSERVER;
using namespace CX2::Application;
using namespace CX2::RPC;
using namespace CX2;

std::string readFile2String(const std::string &fileName)
{
    std::ifstream inputFileStream(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

    std::ifstream::pos_type iFileSize = inputFileStream.tellg();
    inputFileStream.seekg(0, std::ios::beg);

    std::vector<char> bytes(iFileSize);
    inputFileStream.read(bytes.data(), iFileSize);

    return std::string(bytes.data(), iFileSize);
}


void CX2::RPC::Templates::LoginAuth::AddLoginAuthMethods(CX2::Authentication::Manager *auth, CX2::RPC::Fast::FastRPC *fastRPC)
{
    fastRPC->addMethod("authenticate",{&authenticate,auth});
    fastRPC->addMethod("accountChangeAuthenticatedSecret",{&accountChangeAuthenticatedSecret,auth});
    fastRPC->addMethod("getAccountAllSecretsPublicData",{&getAccountAllSecretsPublicData,auth});
    fastRPC->addMethod("passIndexDescription",{&passIndexDescription,auth});
    fastRPC->addMethod("accountSecretPublicData",{&accountSecretPublicData,auth});
    fastRPC->addMethod("passIndexesRequiredForLogin",{&passIndexesRequiredForLogin,auth});
    fastRPC->addMethod("passIndexesUsedByAccount",{&passIndexesUsedByAccount,auth});
    fastRPC->addMethod("passIndexLoginRequired",{&passIndexLoginRequired,auth});

    fastRPC->addMethod("attribExist",{&attribExist,auth});
    fastRPC->addMethod("attribAdd",{&attribAdd,auth});
    fastRPC->addMethod("attribRemove",{&attribRemove,auth});
    fastRPC->addMethod("attribChangeDescription",{&attribChangeDescription,auth});
    fastRPC->addMethod("attribDescription",{&attribDescription,auth});
    fastRPC->addMethod("isAccountSuperUser",{&isAccountSuperUser,auth});

    fastRPC->addMethod("accountExpirationDate",{&accountExpirationDate,auth});

    fastRPC->addMethod("accountValidateAttribute",{&accountValidateAttribute,auth});

    //    fastRPC->addMethod("accountAdd",{&accountAdd,auth});

    fastRPC->addMethod("getStaticContent",{&getStaticContent,auth});

}

json Templates::LoginAuth::accountSecretPublicData(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;

    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        auto v = auth->accountSecretPublicData(JSON_ASSTRING(payload,"accountName",""),JSON_ASUINT(payload,"passIndex",0) );
        for (auto i : v.getMap())
        {
            payloadOut[i.first] = i.second;
        }
    }
    return payloadOut;
}

json Templates::LoginAuth::passIndexesRequiredForLogin(void *obj, const std::string &, const json &)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
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
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
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
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut = auth->passIndexDescription(JSON_ASUINT(payload,"passIndex",0));
    return payloadOut;
}

json Templates::LoginAuth::passIndexLoginRequired(void *obj, const std::string &, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut = auth->passIndexLoginRequired(JSON_ASUINT(payload,"passIndex",0));
    return payloadOut;
}

json Templates::LoginAuth::accountExpirationDate(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut = 0;
    if ( auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
    {
        payloadOut = auth->accountExpirationDate(JSON_ASSTRING(payload,"accountName",""));
    }
    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::authenticate(void * obj, const std::string & connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;

    CX2::Authentication::sClientDetails clientDetails;
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
            CX2::Authentication::getAuthModeFromString(JSON_ASSTRING(payload,"authMode","")),
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
                                            , "Account Authentication Result: %lu - %s, for application %s", JSON_ASUINT(payloadOut,"retCode",0),CX2::Authentication::getReasonText((CX2::Authentication::Reason)JSON_ASUINT(payloadOut,"retCode",0)),getAppNameFromConnectionKey(connectionKey).c_str() );


    payloadOut["retMessage"] = CX2::Authentication::getReasonText((CX2::Authentication::Reason)JSON_ASUINT(payloadOut,"retCode",0));

    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::accountChangeAuthenticatedSecret(void * obj,const std::string & connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;

    json payloadOut;

    std::map<std::string,std::string> mNewSecret;
    for ( const auto & member : payload["newSecret"].getMemberNames() )
    {
        mNewSecret[member] = JSON_ASSTRING(payload["newSecret"],member,"");
    }

    CX2::Authentication::Secret newSecret;
    newSecret.fromMap(mNewSecret);

    CX2::Authentication::sClientDetails clientDetails;
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
                                                                    CX2::Authentication::getAuthModeFromString(JSON_ASSTRING(payload,"authMode","")),
                                                                    JSON_ASSTRING(payload,"challengeSalt","")
                                                                  );


    Globals::getAppLog()->log2(__func__,JSON_ASSTRING(payload,"accountName",""),clientDetails.sIPAddr,
            JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                            , "Account Change Authentication Result: %lu", JSON_ASBOOL(payloadOut,"retCode",false)?1:0);


    return payloadOut;

}

json CX2::RPC::Templates::LoginAuth::accountAdd(void * obj,const std::string & connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;

    json payloadOut;

    std::map<std::string,std::string> mNewSecret;
    for ( const auto & member : payload["newSecret"].getMemberNames() )
    {
        mNewSecret[member] = JSON_ASSTRING(payload,member,"");
    }

    CX2::Authentication::Secret newSecret;
    newSecret.fromMap(mNewSecret);

    CX2::Authentication::sAccountDetails accountDetails;
    accountDetails.sDescription = JSON_ASSTRING(payload["accountDetails"],"description","");
    accountDetails.sEmail = JSON_ASSTRING(payload["accountDetails"],"email","");
    accountDetails.sExtraData = JSON_ASSTRING(payload["accountDetails"],"extraData","");
    accountDetails.sGivenName = JSON_ASSTRING(payload["accountDetails"],"givenName","");
    accountDetails.sLastName = JSON_ASSTRING(payload["accountDetails"],"lastName","");
    CX2::Authentication::sAccountAttribs accountAttribs;
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

json CX2::RPC::Templates::LoginAuth::attribExist(void *obj,const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;

    // This function is important to aplications to understand if they have been installed into the user manager
    json payloadOut;
    payloadOut["retCode"] = auth->attribExist( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") } );
    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::attribAdd(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribAdd( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") },
                                             JSON_ASSTRING(payload,"attribDescription","")
            );


    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Adding Attribute '%s' to Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);

    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::attribRemove(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribRemove( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") });

    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Removing Attribute '%s' from Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);

    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::attribChangeDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["retCode"] = auth->attribChangeDescription( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") },
                                                           JSON_ASSTRING(payload,"attribDescription","")
            );


    Globals::getAppLog()->log0(__func__,JSON_ASBOOL(payloadOut,"retCode",false)? Logs::LEVEL_INFO : Logs::LEVEL_WARN
                                                                        , "Changing description to Attribute '%s' from Application '%s' - %lu", JSON_ASSTRING(payload,"attribName","").c_str(),getAppNameFromConnectionKey(connectionKey).c_str(),  JSON_ASBOOL(payloadOut,"retCode",false)?1:0);


    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::attribDescription(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;
    payloadOut["attribDescription"] = auth->attribDescription( { getAppNameFromConnectionKey(connectionKey), JSON_ASSTRING(payload,"attribName","") } );
    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::getAccountAllSecretsPublicData(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
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

json CX2::RPC::Templates::LoginAuth::isAccountSuperUser(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
    json payloadOut;

    // Security check/container
    if ( !auth->applicationValidateAccount(getAppNameFromConnectionKey(connectionKey),JSON_ASSTRING(payload,"accountName","") ) )
        payloadOut["retCode"] = false;
    else
        payloadOut["retCode"] = auth->isAccountSuperUser( JSON_ASSTRING(payload,"accountName","") );

    return payloadOut;
}

json CX2::RPC::Templates::LoginAuth::accountValidateAttribute(void *obj, const std::string &connectionKey, const json &payload)
{
    CX2::Authentication::Manager * auth = (CX2::Authentication::Manager *)obj;
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
    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/cx2login.js");
    staticContents[i++]["path"] = "/assets/js/cx2login.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/cx2main.js");
    staticContents[i++]["path"] = "/assets/js/cx2main.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/cx2passwd.js");
    staticContents[i++]["path"] = "/assets/js/cx2passwd.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/cx2validations.js");
    staticContents[i++]["path"] = "/assets/js/cx2validations.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/secrets.html");
    staticContents[i++]["path"] = "/secrets.html";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/css/bootstrap.min.css");
    staticContents[i++]["path"] = "/assets/css/bootstrap.min.css";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/jquery-3.5.1.min.js");
    staticContents[i++]["path"] = "/assets/js/jquery-3.5.1.min.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/js/bootstrap.min.js");
    staticContents[i++]["path"] = "/assets/js/bootstrap.min.js";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/css/sticky-footer.css");
    staticContents[i++]["path"] = "/assets/css/sticky-footer.css";

    staticContents[i]["content"] = readFile2String(resourcesPath + "/assets/css/select.css");
    staticContents[i++]["path"] = "/assets/css/select.css";



    return staticContents;
}

std::string CX2::RPC::Templates::LoginAuth::getAppNameFromConnectionKey(const std::string &connectionKey)
{
    std::vector<std::string> splstr;
    split(splstr,connectionKey,boost::is_any_of("."),boost::token_compress_on);
    if (splstr.size())
        return splstr[0];
    return "";
}

