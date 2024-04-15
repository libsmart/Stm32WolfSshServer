/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Stm32WolfSshServer.hpp"
#include "setupNetXThread.hpp"

TX_SEMAPHORE port_12_semaphore;

__attribute__((section(".ccmram")))
char sessionStack[SESSION_STACK_SIZE];
