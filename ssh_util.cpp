/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 * 
 * Version: Aug. 4, 2020
 * 
 */
#include "ssh_util.h"
#include <fstream>

int sftp_transfer_local_to_Server(ssh_session session) {

  sftp_session sftp;
  int access_type = O_WRONLY | O_CREAT | O_TRUNC;
  sftp_file file;
  const char *helloworld = "Hello, World!\n";
  int length = strlen(helloworld);
  int rc, nwritten;
 
  
  
  sftp = sftp_new(session);
  if (sftp == NULL)
  {
    fprintf(stderr, "Error allocating SFTP session: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
 
  rc = sftp_init(sftp);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error initializing SFTP session: code %d.\n",
            sftp_get_error(sftp));
    sftp_free(sftp);
    return rc;
  }
 
  //Source file: Specify local source file location (local path)
  std::ifstream fin("/home/jess/examples.desktop", std::ios::binary);
  
  //Destination file:Specify the server folder location where to put the file
  //Tested OK 8/4/2020
  file = sftp_open(sftp, "/home/jess/CI/examples.desktop",
                   access_type, S_IRWXU);
  if (file == NULL)
  {
    fprintf(stderr, "Can't open file for writing: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
  
   while (fin)
    {
        constexpr size_t max_xfer_buf_size = 10240;
        char buffer[max_xfer_buf_size];
            fin.read(buffer, sizeof(buffer));
            if (fin.gcount() > 0)
            {
                ssize_t nwritten = sftp_write(file, buffer, fin.gcount());
                if (nwritten != fin.gcount())
                {
                    fprintf(stderr, "Can't write data to file: %s\n", ssh_get_error(session));
                    sftp_close(file);
                    return 1;
                }
            }
        }
  
  
  rc = sftp_close(file);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't close the written file: %s\n",
            ssh_get_error(session));
    return rc;
  }
  
  sftp_free(sftp);
  return SSH_OK;
}

/*
 * Creates a directory to target server,
 * then transmit a new file called helloworld.
 */ 
int sftp_helloworld(ssh_session session)
{
  sftp_session sftp;
  int access_type = O_WRONLY | O_CREAT | O_TRUNC;
  sftp_file file;
  const char *helloworld = "Hello, World!\n";
  int length = strlen(helloworld);
  int rc, nwritten;
 
  sftp = sftp_new(session);
  if (sftp == NULL)
  {
    fprintf(stderr, "Error allocating SFTP session: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
 
  rc = sftp_init(sftp);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error initializing SFTP session: code %d.\n",
            sftp_get_error(sftp));
    sftp_free(sftp);
    return rc;
  }
 
  //Create directory
  rc = sftp_mkdir(sftp, "helloworld", S_IRWXU);
  if (rc != SSH_OK)
  {
    if (sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS)
    {
      fprintf(stderr, "Can't create directory: %s\n",
              ssh_get_error(session));
        return rc;
    }
  }
 
  //transfer file
  file = sftp_open(sftp, "helloworld/helloworld.txt",
                   access_type, S_IRWXU);
  if (file == NULL)
  {
    fprintf(stderr, "Can't open file for writing: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
 
  nwritten = sftp_write(file, helloworld, length);
  if (nwritten != length)
  {
    fprintf(stderr, "Can't write data to file: %s\n",
            ssh_get_error(session));
    sftp_close(file);
    return SSH_ERROR;
  }
 
  rc = sftp_close(file);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't close the written file: %s\n",
            ssh_get_error(session));
    return rc;
  }
  
  sftp_free(sftp);
  return SSH_OK;
}

/*
 * use this auto once a public key is paired (loaded to the server).
 */
int authenticate_pubkey_auto(ssh_session session)
{
  int rc;
 
  rc = ssh_userauth_publickey_auto(session, NULL, NULL);
 
  if (rc == SSH_AUTH_ERROR)
  {
     fprintf(stderr, "Authentication failed: %s\n",
       ssh_get_error(session));
     return SSH_AUTH_ERROR;
  }
 
  return rc;
}

/*
 * Using password, this method will be deprecated by using public key
 * authentication. 
 */
int authenticate_password(ssh_session ssh_session) {
  int rc;
  char *password;
    
  password = getpass("Password: ");
  rc = ssh_userauth_password(ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(ssh_session));
    ssh_disconnect(ssh_session);
    ssh_free(ssh_session);
    return -1;
  }
  return rc;
}

int show_remote_files(ssh_session session)
{
  ssh_channel channel;
  int rc;
 
  channel = ssh_channel_new(session);
  if (channel == NULL) return SSH_ERROR;
 
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  
  rc = ssh_channel_request_exec(channel, "ls -l");
    if (rc != SSH_OK)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return rc;
    }
  
  char buffer[256];
    int nbytes;
 
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
      if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
      {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
      }
      nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      fprintf(stderr, " %d bytes returned.", nbytes); 
      return SSH_ERROR;
    }
    else {
        fprintf(stderr, " %d bytes returned.", nbytes); 
    }
    return 0;
}

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

