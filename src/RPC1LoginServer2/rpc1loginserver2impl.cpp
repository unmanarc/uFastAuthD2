#include "rpc1loginserver2impl.h"

#include "../globals.h"

#include <Mantids30/Net_Sockets/socket_tcp.h>
#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Net_Sockets/streams_cryptochallenge.h>
#include <Mantids30/Program_Logs/applog.h>

#include "loginauthproxymethods.h"
#include <inttypes.h>

using namespace Mantids30::Program;
using namespace Mantids30;

bool callbackOnRPCConnect(void *context, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream> socket)
{
    Network::Sockets::NetStreams::CryptoChallenge cstream(socket);

    std::string appName = socket->readStringEx<uint16_t>();
    std::string appKey = Globals::getIdentityManager()->applications->getApplicationAPIKey(appName);

    std::string rpcClientKey = appName + "." + Mantids30::Helpers::Random::createRandomString(8);

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Incoming %sRPC connection from %s (ID: %s)", socket->isSecure() ? "secure " : "", socket->getRemotePairStr().c_str(), rpcClientKey.c_str());

    if (cstream.mutualChallengeResponseSHA256Auth(appKey, true) == std::make_pair(true, true))
    {
        LOG_APP->log0(__func__, Logs::LEVEL_INFO, "%sRPC client '%s' authenticated to application: '%s'", socket->isSecure() ? "secure " : "", rpcClientKey.c_str(), appName.c_str());

        if (Globals::getFastRPC()->processConnection(socket, rpcClientKey, {nullptr, nullptr}) == -2)
        {
            LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Client %s Already Connected, giving up from %s.", rpcClientKey.c_str(), socket->getRemotePairStr().c_str());
        }
    }
    else
    {
        LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Client %s bad API Application Key, giving up from %s.", rpcClientKey.c_str(), socket->getRemotePairStr().c_str());
    }

    LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Connection %sRPC from %s (ID: %s) has been closed.", socket->isSecure() ? "secure " : "", socket->getRemotePairStr().c_str(), rpcClientKey.c_str());
    return true;
}
bool callbackOnProtocolInitFailure(void *context, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream> socket)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Protocol initialization failed for connection from %s", socket->getRemotePairStr().c_str());
    return false;
}

void callbackOnClientAcceptTimeout(void *context, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream> socket)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Client accept timeout for connection from %s", socket->getRemotePairStr().c_str());
}

void callbackOnClientConnectionLimitPerIP(void *context, std::shared_ptr<Mantids30::Network::Sockets::Socket_Stream> socket)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "Connection limit per IP reached for connection from %s", socket->getRemotePairStr().c_str());
}

bool RPC1LoginServer2Impl::createRPCListenerCAB()
{
    if (Globals::getConfig()->get<bool>("LoginRPCServerCAB.Enabled", true))
    {
        std::shared_ptr<Mantids30::Network::Sockets::Socket_TLS> sockRPCListen = std::make_shared<Mantids30::Network::Sockets::Socket_TLS>();

        // Set the SO default security level:
        sockRPCListen->tlsKeys.setSecurityLevel(-1);

        uint16_t listenPort = Globals::getConfig()->get<uint16_t>("LoginRPCServerCAB.ListenPort", 30401);
        std::string listenAddr = Globals::getConfig()->get<std::string>("LoginRPCServerCAB.ListenAddr", "0.0.0.0");

        if (!sockRPCListen->tlsKeys.loadPublicKeyFromPEMFile(Globals::getConfig()->get<std::string>("LoginRPCServerCAB.CertFile", "snakeoil.crt").c_str()))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Login RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Public Key");
            return false;
        }
        if (!sockRPCListen->tlsKeys.loadPrivateKeyFromPEMFile(Globals::getConfig()->get<std::string>("LoginRPCServerCAB.KeyFile", "snakeoil.key").c_str()))
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting Login RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Private Key");
            return false;
        }

        // Set RPC Methods.
        LoginAuthProxyMethods::AddLoginAuthProxyMethods(Globals::getFastRPC());

        // Init the server:
        Network::Sockets::Acceptors::MultiThreaded *multiThreadedAcceptor = new Network::Sockets::Acceptors::MultiThreaded;

        multiThreadedAcceptor->parameters.setMaxConcurrentClients(Globals::getConfig()->get<uint16_t>("LoginRPCServerCAB.MaxClients", 512));
        multiThreadedAcceptor->callbacks.onClientConnected = callbackOnRPCConnect;
        multiThreadedAcceptor->callbacks.contextOnConnect = nullptr;

        multiThreadedAcceptor->callbacks.onProtocolInitializationFailure = callbackOnProtocolInitFailure;
        multiThreadedAcceptor->callbacks.contextOnInitFail = nullptr;

        multiThreadedAcceptor->callbacks.onClientAcceptTimeoutOccurred = callbackOnClientAcceptTimeout;
        multiThreadedAcceptor->callbacks.contextOnTimedOut = nullptr;

        multiThreadedAcceptor->callbacks.onClientConnectionLimitPerIPReached = callbackOnClientConnectionLimitPerIP;
        multiThreadedAcceptor->callbacks.contextonClientConnectionLimitPerIPReached = nullptr;

        if (sockRPCListen->listenOn(listenPort, listenAddr.c_str(), !Globals::getConfig()->get<bool>("LoginRPCServerCAB.ipv6", false)))
        {
            multiThreadedAcceptor->setAcceptorSocket(sockRPCListen);
            multiThreadedAcceptor->startInBackground();
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Accepting RPC clients @%s:%" PRIu16 " via TLS", listenAddr.c_str(), listenPort);
            return true;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockRPCListen->getLastError().c_str());
            return false;
        }
    }
    return true;
}

bool cbPSK(void *data, const std::string &id, std::string *psk)
{
    *psk = Globals::getIdentityManager()->applications->getApplicationAPIKey(id);
    return !psk->empty();
}

bool RPC1LoginServer2Impl::createRPCListenerPAB()
{
    if (Globals::getConfig()->get<bool>("LoginRPCServerPAB.Enabled", true))
    {
        std::shared_ptr<Mantids30::Network::Sockets::Socket_TLS> sockRPCListen = std::make_shared<Mantids30::Network::Sockets::Socket_TLS>();

        // Configure default
        sockRPCListen->tlsKeys.setUsingPSK();
        sockRPCListen->tlsKeys.getPSKServerWallet()->setPSKCallback(&cbPSK, nullptr);

        uint16_t listenPort = Globals::getConfig()->get<uint16_t>("LoginRPCServerPAB.ListenPort", 30402);
        std::string listenAddr = Globals::getConfig()->get<std::string>("LoginRPCServerPAB.ListenAddr", "0.0.0.0");

        // Set RPC Methods.
        LoginAuthProxyMethods::AddLoginAuthProxyMethods(Globals::getFastRPC());

        // Init the server:
        Network::Sockets::Acceptors::MultiThreaded *multiThreadedAcceptor = new Network::Sockets::Acceptors::MultiThreaded;
        multiThreadedAcceptor->parameters.setMaxConcurrentClients(Globals::getConfig()->get<uint16_t>("LoginRPCServerPAB.MaxClients", 512));

        multiThreadedAcceptor->callbacks.onClientConnected = callbackOnRPCConnect;
        multiThreadedAcceptor->callbacks.contextOnConnect = nullptr;

        multiThreadedAcceptor->callbacks.onProtocolInitializationFailure = callbackOnProtocolInitFailure;
        multiThreadedAcceptor->callbacks.contextOnInitFail = nullptr;

        multiThreadedAcceptor->callbacks.onClientAcceptTimeoutOccurred = callbackOnClientAcceptTimeout;
        multiThreadedAcceptor->callbacks.contextOnTimedOut = nullptr;

        multiThreadedAcceptor->callbacks.onClientConnectionLimitPerIPReached = callbackOnClientConnectionLimitPerIP;
        multiThreadedAcceptor->callbacks.contextonClientConnectionLimitPerIPReached = nullptr;

        if (sockRPCListen->listenOn(listenPort, listenAddr.c_str(), !Globals::getConfig()->get<bool>("LoginRPCServerPAB.ipv6", false)))
        {
            multiThreadedAcceptor->setAcceptorSocket(sockRPCListen);
            multiThreadedAcceptor->startInBackground();
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Accepting API KEY RPC clients @%s:%" PRIu16 " via TLS", listenAddr.c_str(), listenPort);
            return true;
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_CRITICAL, "Error starting API KEY RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockRPCListen->getLastError().c_str());
            return false;
        }
    }
    return true;
}
