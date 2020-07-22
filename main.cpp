
/* 
 * File:   main.cpp
 * Project: SSH_Trial_CI
 * Author: Jess Valdez
 *
 * Created on July 20, 2020, 5:06 PM
 * Version: July 22
 * 
 * Note: Trial ssh application using libssh from lissh.org
 * Many functions were taken from https://api.libssh.org/stable/libssh_tutor_guided_tour.html.
 * To statically link the library, right-click on project, go to properties->Linker then add -lssh
 *  
 */

#include <cstdlib>
#include <ostream>
#include <iostream>
#include <errno.h>

#include <stdlib.h>
#include <string.h>

#include "ssh_util.h"

#define PASSWORD_AUTHENTICATION 0
#define PUBKEY_AUTHENTICATION 1

using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {

     ssh_session my_ssh_session;
  int verbosity = SSH_LOG_PROTOCOL;
  int port = 22; 
  int rc;
 
  my_ssh_session = ssh_new();
 
  if (my_ssh_session == NULL)
    exit(-1);
 
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "10.0.0.141");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
 
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
 
  // Verify the server's identity
  // For the source code of verify_knownhost(), check previous example
  if (verify_knownhost(my_ssh_session) < 0)
  {
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
  cout << " Server is verified.." << endl;
  
  /* Authenticate using password. */
  if (PASSWORD_AUTHENTICATION) {
    if (authenticate_password(my_ssh_session) != SSH_AUTH_SUCCESS) { 
        ssh_free(my_ssh_session);
        exit(-1);
    }
  }
  if (PUBKEY_AUTHENTICATION) {
      if (authenticate_pubkey_auto(my_ssh_session) == SSH_AUTH_ERROR){ 
        ssh_free(my_ssh_session);
        exit(-1);
    }
  } 
  

  
  show_remote_files(my_ssh_session);
  
  ssh_free(my_ssh_session);
  cout << "Done..." << endl;
  
    return 0;
}

