/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVERSESSION_HPP
#define LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVERSESSION_HPP

#define EXAMPLE_HIGHWATER_MARK          (0x3FFF8000)

//#include <functional>
//#include "tx_api.h"
#include <main.hpp>
#include "nx_api.h"
#include <wolfssh/ssh.h>

#include "globals.hpp"
#include "Stm32ThreadX.hpp"
#include "Stm32ItmLogger.hpp"
#include "Stm32GcodeRunner.hpp"

#define max(a, b) ((a)>(b)?(a):(b))

using namespace Stm32ThreadX;
using namespace Stm32ThreadX::native;

class Stm32WolfSshServerSession {
public:
    Stm32WolfSshServerSession() {};

    virtual VOID sshServerSessionThread() {
        UINT retNetx = NX_SUCCESS;
        int retWolf = WS_SUCCESS;


        Logger.printf("%lu: sshServerSessionThread()\r\n", HAL_GetTick());

        // Create a new ssh session object from the server context
        wolfSession = wolfSSH_new(wolfContext);
        if (wolfSession == nullptr) {
            Logger.printf("%lu: wolfSSH_new(): Can not create wolfSSH session object\r\n", HAL_GetTick());
            errorHandler();
        }

        // Set the highwater mark (???)
        if (defaultHighwater > 0) {
            wolfSSH_SetHighwaterCtx(wolfSession, (void *) wolfContext);
            wolfSSH_SetHighwater(wolfSession, defaultHighwater);
        }

        // Register the context for the session receive callback functions
        wolfSSH_SetIOReadCtx(wolfSession, this);
        wolfSSH_SetIOWriteCtx(wolfSession, this);

        // Set the username required for the SSH connection
        retWolf = wolfSSH_SetUsername(wolfSession, "admin");
        if (retWolf != WS_SUCCESS) {
            Logger.printf("%lu: wolfSSH_SetUsername() = 0x%02x\r\n", HAL_GetTick(), retWolf);
//                free(wolfContext);
            errorHandler();
        }

        retNetx = nx_tcp_server_socket_accept(socket, NX_WAIT_FOREVER);
        if (retNetx != NX_SUCCESS) {
            Logger.printf("%lu: nx_tcp_server_socket_accept() = 0x%02x\r\n", HAL_GetTick(), retNetx);
            errorHandler();
        }


        retWolf = WS_SUCCESS;
        do {
//            if (retWolf != WS_SUCCESS) tx_thread_relinquish();
            if (retWolf != WS_SUCCESS) tx_thread_sleep(1);
//            tx_thread_sleep(1);
            retWolf = wolfSSH_accept(wolfSession);
            if((retWolf == WS_FATAL_ERROR) && !ioRecvBlock) {
                retWolf=wolfSSH_get_error(wolfSession);
            }
        } while (retWolf == WS_WANT_READ || retWolf == WS_WANT_WRITE);
        if (retWolf != WS_SUCCESS) {
            Logger.printf("%lu: wolfSSH_accept() = %d (%s)\r\n", HAL_GetTick(), retWolf, wolfSSH_ErrorToName(retWolf) );
//            errorHandler();
            assert_param(retWolf == WS_SUCCESS);
//            NX_ASSERT(retWolf == WS_SUCCESS)
        }

        word32 SSH_worker_lastChannel = 0;
//        uint8_t SSH_buffer[10];



        for(;;) {
            if(!ioRecvBlock || !ioSendBlock) tx_thread_sleep(1);

            Stm32GcodeRunner::CommandContext *cmdCtx{};
            while ((cmdCtx = Stm32GcodeRunner::worker->getNextCommandContext(cmdCtx)) != nullptr) {
                if(cmdCtx->outputLength() > 0) {
                    if(SSH_outputstring_wr_pos + cmdCtx->outputLength() <= sizeof SSH_outputstring) {
                        size_t sz = sizeof SSH_outputstring - SSH_outputstring_wr_pos;
                        auto result = cmdCtx->outputRead(reinterpret_cast<char *>(&SSH_outputstring[SSH_outputstring_wr_pos]),
                                                        sz);
                        SSH_outputstring_wr_pos += result;
                    }
                }

                // Recycle command context, if command is finished
                if(cmdCtx->isFinished()) Stm32GcodeRunner::worker->deleteCommandContext(cmdCtx);
            }

            // Write data from SSH_outputstring to wolfSSH stream
            if((SSH_outputstring_wr_pos - SSH_outputstring_rd_pos) > 0) {
                retWolf = wolfSSH_stream_send(wolfSession, &SSH_outputstring[SSH_outputstring_rd_pos], SSH_outputstring_wr_pos - SSH_outputstring_rd_pos);
                if(retWolf > 0) {
                    SSH_outputstring_rd_pos += retWolf;
                    if(SSH_outputstring_wr_pos == SSH_outputstring_rd_pos) {
                        SSH_outputstring_wr_pos = SSH_outputstring_rd_pos = 0;
                        memset(SSH_outputstring, 0, sizeof(SSH_outputstring));
                    }
                }
                // We do not care about errors here, because wolfSSH_stream_read will handle them
            }

            // Handle session without reading, because SSH_inputstring is full
            if(SSH_inputstring_wr_pos >= (sizeof SSH_inputstring)) {
                Logger.printf("%lu: SSH_inputstring buffer full\r\n", HAL_GetTick());
                retWolf = wolfSSH_worker(wolfSession, &SSH_worker_lastChannel);
                if(retWolf == WS_ERROR) {
                    retWolf = wolfSSH_get_error(wolfSession);
                }
                if(retWolf != WS_SUCCESS) {
                    Logger.printf("%lu: wolfSSH_worker() = %d (%s)\r\n", HAL_GetTick(), retWolf,
                                 wolfSSH_ErrorToName(retWolf));
                }

                // Add fake return, so string will be parsed
//                SSH_inputstring[sizeof SSH_inputstring - 1] = '\r';
//                received();
                continue;
            }

            // Read data from woldSSH stream into SSH_inputstring
            retWolf = wolfSSH_stream_read(wolfSession, &SSH_inputstring[SSH_inputstring_wr_pos],
                                              sizeof SSH_inputstring - SSH_inputstring_wr_pos);
            if(retWolf >= 0) {
                // OK, read data
                SSH_inputstring_wr_pos+=retWolf;
                if(SSH_inputstring_wr_pos >= (sizeof SSH_inputstring)) {
                    SSH_inputstring[sizeof SSH_inputstring - 1] = '\r';
                }
                received();
                continue;
            } else if (retWolf == WS_EOF) {
                // End session
                closeSession();
                break;
            } else if (retWolf == WS_REKEYING) {
                continue;
            } else if (retWolf == WS_FATAL_ERROR) {
                retWolf = wolfSSH_get_error(wolfSession);
            }

            if(!ioRecvBlock && retWolf == WS_WANT_READ) continue;
            if(!ioSendBlock && retWolf == WS_WANT_WRITE) continue;

            Logger.printf("%lu: wolfSSH_stream_read() = %d (%s)\r\n", HAL_GetTick(), retWolf, wolfSSH_ErrorToName(retWolf));
            closeSession();
            break;
        }

        errorHandler();
    }


    virtual void closeSession() {
        Logger.printf("%lu: Stm32WolfSshServerSession::closeSession()\r\n", HAL_GetTick());
        wolfSSH_stream_exit(wolfSession, 0);
        nx_tcp_socket_disconnect(socket, NX_WAIT_FOREVER);
        nx_tcp_server_socket_unaccept(socket);
        wolfSSH_free(wolfSession);
        wolfSession = nullptr;
    }


    virtual void received() {
//        Debugger_log(DBG, "%lu: unparsed buffer: '%.*s'", HAL_GetTick(), SSH_inputstring_wr_pos - SSH_inputstring_rd_pos_parsed, SSH_inputstring + SSH_inputstring_rd_pos_parsed);
//        Debugger_log(DBG, "%lu: SSH_inputstring_rd_pos_parsed=%3d  |  SSH_inputstring_rd_pos=%3d  |  SSH_inputstring_wr_pos=%3d", HAL_GetTick(), SSH_inputstring_rd_pos_parsed, SSH_inputstring_rd_pos, SSH_inputstring_wr_pos);

        for (uint16_t pos=SSH_inputstring_rd_pos; pos < SSH_inputstring_wr_pos; pos++) {

            // Echo
            if(SSH_inputstring[pos] == '\r') {
                appendOutputString("\r\n");
            }
            if(SSH_inputstring[pos] >= 32) {
                appendOutputString(reinterpret_cast<byte *>(&SSH_inputstring[pos]), pos + 1 - SSH_inputstring_rd_pos);
            }

            switch(SSH_inputstring[pos]) {
                case 0x04: // Ctrl-D
                    SSH_inputstring_rd_pos_parsed = pos + 1;
                    closeSession();
                    break;

                case 0x05: // Ctrl-E
                    SSH_inputstring_rd_pos_parsed = pos + 1;
                    dump_stats();
                    break;

                case 0x06: // Ctrl-F
                    SSH_inputstring_rd_pos_parsed = pos + 1;
                    wolfSSH_TriggerKeyExchange(wolfSession);
                    break;

                case '\r': // Enter
                {
//                    Debugger_log(DBG, "%lu: SSH_inputstring_rd_pos_parsed=%3d  |  SSH_inputstring_wr_pos=%3d  |  pos=%3d", HAL_GetTick(), SSH_inputstring_rd_pos_parsed, SSH_inputstring_wr_pos, pos);
//                    Debugger_log(DBG, "%lu: parse: '%.*s'", HAL_GetTick(), pos - SSH_inputstring_rd_pos_parsed, SSH_inputstring + SSH_inputstring_rd_pos_parsed);

                    Stm32GcodeRunner::AbstractCommand *cmd{};
                    auto ret = Stm32GcodeRunner::parser->parseString(
                            cmd,
                            reinterpret_cast<const char *>(SSH_inputstring + SSH_inputstring_rd_pos_parsed),
                            pos - SSH_inputstring_rd_pos_parsed);
                    SSH_inputstring_rd_pos_parsed = pos + 1;
                    if (ret == Stm32GcodeRunner::Parser::parserReturn::OK) {
                        Logger.printf("Found command: %s\r\n", cmd->getName());
                        Stm32GcodeRunner::CommandContext *cmdCtx{};
                        Stm32GcodeRunner::worker->createCommandContext(cmdCtx, cmd);
                    } else {
                        appendOutputString("ERROR: UNKNOWN COMMAND\r\n");
                    }
                    break;
                }

                default:
                    break;
            }

            SSH_inputstring_rd_pos = pos + 1;
        }


        if(SSH_inputstring_rd_pos_parsed == SSH_inputstring_wr_pos) {
            Logger.printf("%lu: Clearing SSH_inputstring\r\n", HAL_GetTick());
            SSH_inputstring_rd_pos_parsed = SSH_inputstring_rd_pos = SSH_inputstring_wr_pos = 0;
            memset(SSH_inputstring, 0, sizeof(SSH_inputstring));
        }

    }

    virtual void setServerContext(WOLFSSH_CTX *serverCtx) {
        wolfContext = serverCtx;
    }

    virtual void setSocket(NX_TCP_SOCKET *sock) {
        socket = sock;
    }

    virtual uint16_t getThreadId() = 0;


    virtual void appendOutputString(const uint8_t *buffer, size_t size) {
        if(SSH_outputstring_wr_pos + size > sizeof SSH_outputstring) {
            Logger.printf("%lu: appendOutputString() Buffer overflow\r\n", HAL_GetTick());
            return;
        }
        // TODO: This is dangerous
        memcpy(reinterpret_cast<void *>(&SSH_outputstring[SSH_outputstring_wr_pos]), buffer, size);
        SSH_outputstring_wr_pos += size;
    }

    virtual void appendOutputString(const char *str) {
        if(SSH_outputstring_wr_pos + strlen(str) > sizeof SSH_outputstring) {
            Logger.printf("%lu: appendOutputString() Buffer overflow\r\n", HAL_GetTick());
            return;
        }
        strcpy(reinterpret_cast<char *>(&SSH_outputstring[SSH_outputstring_wr_pos]), str);
        SSH_outputstring_wr_pos += strlen(str);
    }

    virtual void appendOutputString(const char ch) {
        if(SSH_outputstring_wr_pos + 1 > sizeof SSH_outputstring) {
            Logger.printf("%lu: appendOutputString() Buffer overflow\r\n", HAL_GetTick());
            return;
        }
        SSH_outputstring[SSH_outputstring_wr_pos] = ch;
        SSH_outputstring_wr_pos++;
    }

public:
    NX_TCP_SOCKET *socket;
    // Used for ioRecv
    NX_PACKET *packet{};
    ULONG packet_length{};
    ULONG packet_offset{};
    bool ioRecvBlock=false;
    bool ioSendBlock=false;

protected:
    WOLFSSH_CTX *wolfContext;
    WOLFSSH *wolfSession{};

    uint8_t SSH_outputstring[1024] = {0};
    uint16_t SSH_outputstring_wr_pos = 0;
    uint16_t SSH_outputstring_rd_pos = 0;

    uint8_t SSH_inputstring[128] = {0};
    uint16_t SSH_inputstring_wr_pos = 0;
    uint16_t SSH_inputstring_rd_pos = 0;
    uint16_t SSH_inputstring_rd_pos_parsed = 0;

    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;


    [[noreturn]] virtual VOID errorHandler() {
        for (;;) {
            tx_thread_sleep(1);
        }
    }

    int dump_stats() {
        Logger.println("dump_stats(...)");
        char stats[128];
        word32 statsSz;
        word32 txCount, rxCount, seq, peerSeq;

        wolfSSH_GetStats(wolfSession, &txCount, &rxCount, &seq, &peerSeq);

        WSNPRINTF(stats, sizeof(stats),
                  "Statistics for Thread #%u:\r\n"
                  "  txCount = %u\r\n  rxCount = %u\r\n"
                  "  seq = %u\r\n  peerSeq = %u\r\n",
                  this->getThreadId(), txCount, rxCount, seq, peerSeq);
        statsSz = (word32) strlen(stats);

        fprintf(stderr, "%s", stats);
        return wolfSSH_stream_send(wolfSession, (byte *) stats, statsSz);
    }

private:
//    Stm32GcodeRunner::CommandContext cmdCtx;

};


#endif //LIBSMART_STM32WOLFSSHSERVER_STM32WOLFSSHSERVERSESSION_HPP
