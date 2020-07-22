/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ssh_util.h
 * Author: jess
 *
 * Created on July 20, 2020, 5:13 PM
 */

#ifndef SSH_UTIL_H
#define SSH_UTIL_H

#include <string.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <ostream>
#include <iostream>

int show_remote_files(ssh_session session);
int verify_knownhost(ssh_session session);
int authenticate_password(ssh_session ssh_session);
int authenticate_pubkey_auto(ssh_session session);

#endif /* SSH_UTIL_H */

