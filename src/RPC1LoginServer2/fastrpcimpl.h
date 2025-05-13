#pragma once

#include <Mantids30/Protocol_FastRPC1/fastrpc.h>


using namespace Mantids30::Network::Protocols::FastRPC;

class FastRPCImpl : public FastRPC1
{
public:
    FastRPCImpl(uint32_t threadsCount = 16, uint32_t taskQueues = 24) : FastRPC1(threadsCount,taskQueues)
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

