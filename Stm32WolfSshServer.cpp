/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Stm32WolfSshServer.hpp"
#include "sshKeys.hpp"
#include "setupNetXThread.hpp"

VOID Stm32WolfSshServer::mainSshServerThread() {
    UINT ret = NX_SUCCESS;
    bool SSH_state_changed = true;
    UINT threadCount = 0;
    int SSH_accept_status = WS_FATAL_ERROR;
    int SSH_worker_status = WS_FATAL_ERROR;
    int SSH_ret = WS_FATAL_ERROR;
    word32 SSH_worker_lastChannel = 0;
    int SSH_recv_result = -1;
    uint8_t SSH_buffer[1] = {0};

    Debugger_log(DBG, "Stm32WolfSshServer::mainSshServerThread()");

    ULONG available = 0, total = 0;
    CHAR *bytePool_name = nullptr;


    for (;;) {
        SSH_state_changed = (SSH_state != SSH_state_last);
        SSH_state_last = SSH_state;

        /*
        ret = tx_byte_pool_info_get(&nx_app_byte_pool, &bytePool_name, &available, &total, (TX_THREAD **)TX_NULL, (ULONG *)TX_NULL, (TX_BYTE_POOL **)TX_NULL);
        if(ret != TX_SUCCESS) {
            available = total = 0;
        }
         */


        switch (SSH_state) {
            case SSH_INIT:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_INIT (%lu / %lu)", available, total);

                SSH_inputstring_pos = 0;
                memset(SSH_inputstring, 0, sizeof(SSH_inputstring));

                if (wolfSSH_Init() != WS_SUCCESS) {
                    Debugger_log(DBG, "Couldn't initialize wolfSSH.\n");
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                }

//                wolfSSH_SetLoggingCb(wolfSSH_LoggingCallback);
                wolfSSH_Debugging_ON();


                ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, nullptr);
                if (ctx == nullptr) {
                    Debugger_log(DBG, "Couldn't allocate SSH CTX data.\n");
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                }

                wolfSSH_SetUserAuth(ctx, wsUserAuth);
//                wolfSSH_SetUserAuthResult(ctx, wsUserAuthResult);

                wolfSSH_CTX_SetBanner(ctx, serverBanner);

                wolfSSH_CTX_SetWindowPacketSize(ctx, 1024 * 4, 1024);

//                keyLoadBuf = (byte*)WMALLOC(EXAMPLE_KEYLOAD_BUFFER_SZ, NULL, 0);
//                bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;
//                WMEMCPY(keyLoadBuf, (byte*)rsa_key_der_2048, sizeof_rsa_key_der_2048);
//                bufSz = sizeof_rsa_key_der_2048;

//                if ((SSH_ret=wolfSSH_CTX_UsePrivateKey_buffer(ctx, rsa_key_der_2048, sizeof_rsa_key_der_2048, WOLFSSH_FORMAT_ASN1)) < 0) {
                if ((SSH_ret = wolfSSH_CTX_UsePrivateKey_buffer(ctx, ecc_key_der_256, sizeof_ecc_key_der_256,
                                                                WOLFSSH_FORMAT_ASN1)) < 0) {
                    Debugger_log(DBG, "Couldn't use first key buffer: %s (%i)", wolfSSH_ErrorToName(SSH_ret),
                                 SSH_ret);
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                }


                SSH_state = SSH_SOCKET;
                break;

            case SSH_SOCKET: {
                char socket_name[] = "SSH socket";
                if (SSH_state_changed) Debugger_log(DBG, "SSH_SOCKET (%lu / %lu)", available, total);
                ret = nx_tcp_socket_create(&ipInstance_struct, &SSH_sock, socket_name,
                                           NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                           NX_NULL, thread_1_disconnect_received);
                if (ret != NX_SUCCESS) {
                    // No socket created
                    Debugger_log(DBG, "ERROR: nx_tcp_socket_create(): %i", ret);
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                }
                SSH_state = SSH_BIND;
                break;
            }

            case SSH_BIND:
                SSH_state = SSH_BIND;
                if (SSH_state_changed) Debugger_log(DBG, "SSH_BIND (%lu / %lu)", available, total);
                SSH_state = SSH_LISTEN;
                break;

            case SSH_LISTEN:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_LISTEN (%lu / %lu)", available, total);
                ret = nx_tcp_server_socket_listen(&ipInstance_struct, SSH_PORT, &SSH_sock, 5,
                                                  thread_1_connect_received);
                if (ret != NX_SUCCESS) {
                    Debugger_log(DBG, "ERROR: lwip_listen()");
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                } else {

                    threadCtx = (thread_ctx_t *) malloc(sizeof(thread_ctx_t));
                    if (threadCtx == nullptr) {
                        Debugger_log(DBG, "Couldn't allocate thread context data");
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }
                    memset(threadCtx, 0, sizeof *threadCtx);

                    threadCtx->ssh = wolfSSH_new(ctx);
                    if (threadCtx->ssh == nullptr) {
                        free(threadCtx);
                        Debugger_log(DBG, "Couldn't allocate SSH data");
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }

//                    wolfSSH_SetUserAuthCtx(ssh, &pwMapList);

                    if (defaultHighwater > 0) {
                        wolfSSH_SetHighwaterCtx(threadCtx->ssh, (void *) threadCtx->ssh);
                        wolfSSH_SetHighwater(threadCtx->ssh, defaultHighwater);
                    }


                    SSH_state = SSH_IDLE;
                }
                break;

            case SSH_IDLE:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_IDLE (%lu / %lu)", available, total);

                ret = nx_tcp_server_socket_accept(&SSH_sock, NX_WAIT_FOREVER);
                if (ret == NX_SUCCESS) {

/*
                    if(wolfSSH_set_fd(threadCtx->ssh, (int) SSH_sock) != WS_SUCCESS) {
                        free(threadCtx);
                        Debugger_log(DBG, "ERROR: wolfSSH_set_fd()");
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                    }
*/


                    wolfSSH_SetIORecv(ctx, ioRecv);
                    wolfSSH_SetIOReadCtx(threadCtx->ssh, threadCtx);
                    wolfSSH_SetIOSend(ctx, ioSend);
                    wolfSSH_SetIOWriteCtx(threadCtx->ssh, threadCtx);

                    if (wolfSSH_SetUsername(threadCtx->ssh, "admin") != WS_SUCCESS) {
                        free(threadCtx);
                        Debugger_log(DBG, "ERROR: wolfSSH_SetUsername()");
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                    }


//                    threadCtx->ssh = ssh;
                    threadCtx->sock = &SSH_sock;
                    threadCtx->id = threadCount++;
                    threadCtx->nonBlock = 0;

                    SSH_state = SSH_ACCEPT_SSH;
                }
                break;

            case SSH_ACCEPT_SSH:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_ACCEPT_SSH (%lu / %lu)", available, total);

                // https://www.wolfssl.com/documentation/manuals/wolfssh/chapter13.html#wolfssh_accept
//                server_worker(threadCtx);

                SSH_accept_status = wolfSSH_accept(threadCtx->ssh);
                if ((SSH_accept_status == WS_WANT_READ) || (SSH_accept_status == WS_WANT_WRITE)) {
                    // Call wolfSSH_accept() again
                } else if (SSH_accept_status == WS_SUCCESS) {
                    // Success
                    SSH_state = SSH_WORKER;
                    break;
                } else {
                    Debugger_log(DBG, "wolfSSH_accept(): %s (%i)", wolfSSH_ErrorToName(SSH_accept_status),
                                 SSH_accept_status);
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                }

                break;

            case SSH_WORKER:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_WORKER (%lu / %lu)", available, total);
                SSH_worker_status = wolfSSH_worker(threadCtx->ssh, &SSH_worker_lastChannel);
                if (SSH_worker_status == WS_CHAN_RXD) {
                    SSH_recv_result = wolfSSH_ChannelIdRead(threadCtx->ssh, SSH_worker_lastChannel, SSH_buffer,
                                                            sizeof(SSH_buffer));
                    if (SSH_recv_result < 0) {
                        Debugger_log(DBG, "wolfSSH_ChannelIdRead(): %s (%i)", wolfSSH_ErrorToName(SSH_recv_result),
                                     SSH_recv_result);
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    } else if (SSH_recv_result == 1) {
                        if (SSH_inputstring_pos < sizeof(SSH_inputstring)) {
                            SSH_inputstring[SSH_inputstring_pos++] = SSH_buffer[0];
//                            Debugger_log(DBG, "%x", SSH_buffer[0]);
//                            if (SSH_buffer[0] == 0x03) /* Ctrl-C */ SSH_state = SSH_CLOSE;
                            if (SSH_buffer[0] == 0x04) /* Ctrl-D */ SSH_state = SSH_CLOSE;
                            if (SSH_buffer[0] == 0x05) /* Ctrl-E */ dump_stats(threadCtx);
                            if (SSH_buffer[0] == 0x06) /* Ctrl-F */ wolfSSH_TriggerKeyExchange(threadCtx->ssh);
                            if (SSH_buffer[0] == '\r') SSH_state = SSH_RECEIVED;
                        } else {
                            Debugger_log(DBG, "ERROR: buffer overflow");
                            SSH_state = SSH_RECEIVED;
                        }
                    } else if (SSH_recv_result > 1) {
                        Debugger_log(DBG, "ERROR: NOT SUPPORTED");
                        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                        SSH_state = SSH_ERROR;
                        break;
                    }

                } else if (SSH_worker_status == WS_SUCCESS) {
                    // Success => repeat
                } else {
                    Debugger_log(DBG, "wolfSSH_worker(): %s (%i)", wolfSSH_ErrorToName(SSH_worker_status),
                                 SSH_worker_status);
                    tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
                    SSH_state = SSH_ERROR;
                    break;
                }
                break;

            case SSH_RECEIVED: {
                Debugger_log(DBG, "received: %s", SSH_inputstring);
//                lwip_write(newsock, "ok\r\n", 4);
                char message[] = "ok\r\n";
                wolfSSH_stream_send(threadCtx->ssh, reinterpret_cast<byte *>(message), strlen(message));
                SSH_inputstring_pos = 0;
                memset(SSH_inputstring, 0, sizeof(SSH_inputstring));
                SSH_state = SSH_WORKER;
                if (SSH_state_changed) Debugger_log(DBG, "SSH_RECEIVED (%lu / %lu)", available, total);
                break;
            }

            case SSH_CLOSE:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_CLOSE (%lu / %lu)", available, total);
                wolfSSH_stream_exit(threadCtx->ssh, 0);
                nx_tcp_socket_disconnect(threadCtx->sock, NX_WAIT_FOREVER);
                nx_tcp_server_socket_unaccept(threadCtx->sock);
                nx_tcp_server_socket_relisten(&ipInstance_struct, SSH_PORT, threadCtx->sock);
                wolfSSH_free(threadCtx->ssh);
                free(threadCtx);

//                wolfSSH_CTX_free(ctx);
//                if (wolfSSH_Cleanup() != WS_SUCCESS) {
//                    Debugger_log(DBG, "Couldn't clean up wolfSSH");
//                    osDelay(pdMS_TO_TICKS(1000));
//                    SSH_state = SSH_ERROR;
//                    break;
//                }

                SSH_state = SSH_IDLE;

                break;


            case SSH_ERROR:
                if (SSH_state_changed) Debugger_log(DBG, "SSH_ERROR (%lu / %lu)", available, total);
                break;

            default:
                if (SSH_state_changed) Debugger_log(DBG, "SSH default");

        }


        tx_thread_sleep(1);
    }




}
