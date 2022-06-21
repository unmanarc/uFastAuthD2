#include "loginrpcserverimpl.h"

#include <inttypes.h>

#include <mdz_net_sockets/socket_tls.h>
#include <mdz_net_sockets/socket_acceptor_multithreaded.h>
#include <mdz_net_sockets/cryptostream.h>
#include <mdz_prg_logs/applog.h>

#include "globals.h"
#include "defs.h"
#include "loginauthmethods.h"

using namespace AUTHSERVER::RPC;

using namespace Mantids::Application;
using namespace Mantids::RPC;
using namespace Mantids;

LoginRPCServerImpl::LoginRPCServerImpl()
{
}

bool LoginRPCServerImpl::callbackOnRPCConnect(void *, Mantids::Network::Streams::StreamSocket *sock, const char * remoteAddr, bool secure)
{
    Network::Streams::CryptoStream cstream(sock);
   // Mantids::Network::TLS::Socket_TLS * tlsSock = (Mantids::Network::TLS::Socket_TLS *)sock;

    std::string appName = sock->readStringEx<uint16_t>();
    std::string appKey = Globals::getAuthManager()->applicationKey(appName);

    std::string rpcClientKey = appName + "." + Mantids::Helpers::Random::createRandomString(8);

    Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO, "Incomming %sRPC connection from %s (ID: %s)", secure?"secure ":"", remoteAddr, rpcClientKey.c_str());

    if (cstream.mutualChallengeResponseSHA256Auth(appKey,true) == std::make_pair(true,true))
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO, "%sRPC client '%s' authenticated to application: '%s'", secure?"secure ":"", rpcClientKey.c_str(), appName.c_str());

        if (Globals::getFastRPC()->processConnection(sock,rpcClientKey,{nullptr,nullptr})==-2)
        {
            Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Client %s Already Connected, giving up from %s.", rpcClientKey.c_str(), remoteAddr);
        }
    }
    else
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Client %s bad API Application Key, giving up from %s.", rpcClientKey.c_str(), remoteAddr);
    }


    Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO, "Connection %sRPC from %s (ID: %s) has been closed.", secure?"secure ":"", remoteAddr, rpcClientKey.c_str());
    return true;
}

bool LoginRPCServerImpl::createRPCListener()
{
    Mantids::Network::TLS::Socket_TLS * sockRPCListen = new Mantids::Network::TLS::Socket_TLS;

    uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("LoginRPCServer.ListenPort",40442);
    std::string listenAddr = Globals::getConfig_main()->get<std::string>("LoginRPCServer.ListenAddr","0.0.0.0");

    if (!sockRPCListen->setTLSPublicKeyPath( Globals::getConfig_main()->get<std::string>("LoginRPCServer.CertFile","snakeoil.crt").c_str() ))
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Public Key");
        return false;
    }
    if (!sockRPCListen->setTLSPrivateKeyPath( Globals::getConfig_main()->get<std::string>("LoginRPCServer.KeyFile","snakeoil.key").c_str() ))
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Login RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Private Key");
        return false;
    }

    Globals::setFastRPC(new FastRPCImpl);

    // Set RPC Methods.
    Mantids::RPC::Templates::LoginAuth::AddLoginAuthMethods(
                Globals::getAuthManager(),
                Globals::getFastRPC());

    // Init the server:
    Network::Sockets::Acceptors::Socket_Acceptor_MultiThreaded * multiThreadedAcceptor = new Network::Sockets::Acceptors::Socket_Acceptor_MultiThreaded;
    multiThreadedAcceptor->setMaxConcurrentClients( Globals::getConfig_main()->get<uint16_t>("LoginRPCServer.MaxClients",512) );
    multiThreadedAcceptor->setCallbackOnConnect(callbackOnRPCConnect,nullptr);

    if (sockRPCListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("LoginRPCServer.ipv6",false) ))
    {
        multiThreadedAcceptor->setAcceptorSocket(sockRPCListen);
        multiThreadedAcceptor->startThreaded();
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_INFO,  "Accepting RPC clients @%s:%" PRIu16 " via TLS", listenAddr.c_str(), listenPort);
        return true;
    }
    else
    {
        Globals::getAppLog()->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockRPCListen->getLastError().c_str());
        return false;
    }
}

void FastRPCImpl::eventUnexpectedAnswerReceived(Fast::FastRPC_Connection *, const std::string &)
{
    Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Error");

}

void FastRPCImpl::eventFullQueueDrop(Fast::sFastRPCParameters *)
{
    Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Error");

}

void FastRPCImpl::eventRemotePeerDisconnected(const std::string &, const std::string &, const json &)
{
    Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Error");

}

void FastRPCImpl::eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &)
{
    Globals::getAppLog()->log0(__func__,Logs::LEVEL_ERR, "RPC Error");

}
