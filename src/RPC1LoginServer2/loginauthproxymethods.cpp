#include "loginauthproxymethods.h"
#include "Mantids30/Helpers/json.h"
#include <Mantids30/Server_RESTfulWebAPI/engine.h>
#include <memory>
#include "globals.h"

using namespace Mantids30::Network;
using namespace Mantids30::Network::Servers;
using namespace Mantids30::API::RESTful;
using namespace Mantids30::API;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::Network::Protocols::MIME;
using namespace Mantids30::Network::Protocols;
using namespace Mantids30::Network::Protocols::FastRPC;
using namespace Mantids30::Memory::Streams;

void LoginAuthProxyMethods::AddLoginAuthProxyMethods(
    FastRPC1 *fastRPC)
{
    fastRPC->addMethod("proxy", {&proxy, nullptr});
}

/**
 * @brief proxy Handles the login authentication proxy request.
 *
 * This method creates a virtual connection to the web login server,
 * sends session data, and returns the response from the server.
 *
 * @param context Unused shared pointer context
 * @param key Unused key parameter
 * @param parameters JSON object containing the session data and remote peer information
 * @param cntObj Unused shared pointer to an object
 * @param cntData Unused string data
 * @return A JSON object containing the response from the web login server.
 */
json LoginAuthProxyMethods::proxy(
    std::shared_ptr<void> context, const std::string &key, const json &parameters, std::shared_ptr<void> cntObj, const std::string &cntData)
{
    json response;

    // Get the web login server instance
    auto webLoginServer = Globals::getWebLoginServer();

    // Extract session data and remote peer information from parameters
    std::string sessionData = JSON_ASSTRING(parameters, "data", "");
    std::string remotePeer = JSON_ASSTRING(parameters, "remotePeer", "");

    // Create a virtual dummy socket to simulate the connection
    auto virtualSocket = std::make_shared<Sockets::Socket_Stream_Dummy>();

    // Set the remote peer override for the virtual socket
    virtualSocket->setRemotePairOverride(remotePeer.c_str());

    // Append session data to the sender stream of the virtual socket
    virtualSocket->getSender()->append(sessionData.data(), sessionData.size());

    // Handle the virtual connection on the web login server
    webLoginServer->handleVirtualConnection(virtualSocket);

    // Retrieve and store the response from the receiver stream of the virtual socket
    response["data"] = virtualSocket->getReceiver()->toString();
    return response;
}
