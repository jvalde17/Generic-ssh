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
 * Version: Aug 4, 2020
 */

#ifndef SSH_UTIL_H
#define SSH_UTIL_H

#include <string.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <ostream>
#include <iostream>

int show_remote_files(ssh_session session);
int verify_knownhost(ssh_session session);
int authenticate_password(ssh_session ssh_session);
int authenticate_pubkey_auto(ssh_session session);

int sftp_helloworld(ssh_session session);
int sftp_transfer_local_to_Server(ssh_session session);

#endif /* SSH_UTIL_H */

