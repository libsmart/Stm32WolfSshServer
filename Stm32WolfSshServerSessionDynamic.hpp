/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBSMART_STM32WOLFSSHSERVERSESSIONDYNAMIC_HPP
#define LIBSMART_STM32WOLFSSHSERVERSESSIONDYNAMIC_HPP

//#include <functional>
//#include "tx_api.h"
//#include "nx_api.h"

#include <wolfssh/ssh.h>
//#include "setupNetXThread.hpp"

#include "Stm32ThreadxThread.hpp"
#include "Stm32ItmLogger.h"
#include "Stm32WolfSshServerSession.hpp"

using namespace Stm32ThreadxThread;
using namespace Stm32ThreadxThread::native;

extern Debugger *DBG;

//template<const std::size_t STACK_SIZE_BYTES>
class Stm32WolfSshServerSessionDynamic : public Stm32WolfSshServerSession, public Stm32ThreadxThread::thread {
public:
    /*
    Stm32WolfSshServerSession(Stm32WolfSshServer<STACK_SIZE_BYTES> *stm32WolfSshServer, void *pstack,
                              std::uint32_t stack_size,
                              priority prio, const char *name) : stm32WolfSshServer(
            stm32WolfSshServer), thread(pstack, stack_size,
                                        &Stm32ThreadxThread::BOUNCE(Stm32WolfSshServerSession, sshServerSessionThread),
                                        (ULONG) this, prio, name) {};
                                        */


    Stm32WolfSshServerSessionDynamic(void *pstack,
                                     std::uint32_t stack_size,
                                     priority prio, const char *name) : thread(pstack, stack_size,
                                                                               &Stm32ThreadxThread::BOUNCE(
                                                                                       Stm32WolfSshServerSession,
                                                                                       sshServerSessionThread),
                                                                               (ULONG) this, prio, name) {};


    virtual ~Stm32WolfSshServerSessionDynamic() {
        if (wolfSession != nullptr) Stm32WolfSshServerSessionDynamic::closeSession();
    }

    void closeSession() override {
        Stm32WolfSshServerSession::closeSession();
        this->terminate();
    }


    uint16_t getThreadId() override {
        return getId();
    }

private:
    Stm32WolfSshServerSessionDynamic() = delete;

//    Stm32WolfSshServer<STACK_SIZE_BYTES> *stm32WolfSshServer{};

};


#endif //LIBSMART_STM32WOLFSSHSERVERSESSIONDYNAMIC_HPP
