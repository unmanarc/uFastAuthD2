#ifndef RPC_H
#define RPC_H

#include <Mantids29/Net_Sockets/socket_stream_base.h>
#include <Mantids29/Protocol_FastRPC1/fastrpc.h>

namespace AUTHSERVER { namespace RPC {

class FastRPCImpl : public Mantids29::Network::Protocols::FastRPC::FastRPC1
{
public:
    FastRPCImpl(uint32_t threadsCount = 16, uint32_t taskQueues = 24) : Mantids29::Network::Protocols::FastRPC::FastRPC1(threadsCount,taskQueues)
    {
    }
    virtual ~FastRPCImpl()
    {
    }

protected:
    // TODO: report back to the manager_remote.


    void eventUnexpectedAnswerReceived(FastRPC1::Connection *, const std::string &) override;
    void eventFullQueueDrop(FastRPC1::ThreadParameters *) override;
    void eventRemotePeerDisconnected(const std::string &, const std::string &, const json &) override;
    void eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &) override;
private:

};


class LoginRPCServerImpl
{
public:
    LoginRPCServerImpl();
    static bool createRPCListenerCAB();
    static bool createRPCListenerPAB();
//    static void callbackOnRPCConnected(const std::string &key, void * data);

private:
    static bool callbackOnRPCConnect(void *, Mantids29::Network::Sockets::Socket_Stream_Base *sock, const char *remoteAddr, bool secure);
};

}}

#endif // RPC_H
