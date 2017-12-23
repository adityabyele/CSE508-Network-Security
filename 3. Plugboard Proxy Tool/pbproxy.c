#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pthread.h>
#include<openssl/rand.h>
#include <openssl/aes.h>

#define BF_SZ 4096
void* spwn_srvr(void* context);
void server(int);
void client(char*, int, unsigned char* key);
void* client_recv(void* context);
void server1(int lstng_prt, char* dst_ip, int dst_prt, unsigned char* key);
void* msgTransfer(void* context);

struct c_data{
  int client_socket;
  char* dst_ip;
  int dst_prt;
  unsigned char* key;
  unsigned char* iv1;
  unsigned char* iv2;
};

struct ctr_state{
  unsigned char ivec[16];
  unsigned int num;
  unsigned char ecount[16];
};

struct msgParams{
  int src_socket, dst_socket, cryptOp;
  unsigned char* key;
  unsigned char* iv;
};

int init_ctr(struct ctr_state *state, const unsigned char iv[8]){
    state->num = 0;
    memset(state->ecount, 0, 16);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
}


int main(int argc, char* argv[]){
  int option, i, isServer=0, lstng_prt=0, dst_prt=0, new_socket, c;
  FILE* f_ptr;
  char * f_pth;
  char *dst_ip;
  unsigned char key[16];

  /* get command line arguements*/
  while((option = getopt(argc, argv, "l:k:"))!=-1){
    switch(option){
      case 'l':
        isServer = 1;
        lstng_prt = atoi(optarg);    //get listening port
        break;
      case 'k':
        f_pth = optarg; //key file path
        break;
      case '?':
        if (optopt == 'l'|| optopt == 'k')
          return (2);
        else if (isprint (optopt))
          return (2);
        else
          return (2);
        default:
          abort();
    }
  }

  /*get destination ip and port*/
  if(argc - optind  == 2){
    dst_ip = argv[optind];
    dst_prt = atoi(argv[optind+1]);
  }
  else{
    return (2);
  }

  /*get key from key file*/
  f_ptr = fopen(f_pth,"r");
  if(f_ptr == NULL){
    printf("Cannot open file\n");
    return(2);
  }

  fgets(key, 17, f_ptr);

  if(isServer == 1){
    /*start server*/
    server1(lstng_prt, dst_ip, dst_prt, key);
  }
  else{
    /*start client*/
    client(dst_ip, dst_prt, key);
  }
}


/*server function handles the job of pbproxy server*/
void server1(int lstng_prt, char* dst_ip, int dst_prt, unsigned char* key){
  int srvr_socket, client_socket, addr_len;
  pthread_t srvr_thrd;//thread to launch thread for each client
  unsigned char iv1[8], iv2[8]; //ivs one per encryption-decryption line
  struct sockaddr_in srvr, client;
  struct c_data para; //passing parameters to srvr_thrd

  /*create socket and listen on specified port*/
  srvr_socket = socket(AF_INET, SOCK_STREAM, 0);
  //excp failed to create socket
  if(srvr_socket<0){
    printf("Could not create socket\n");
    return;
  }

  srvr.sin_family = AF_INET;
  srvr.sin_addr.s_addr = INADDR_ANY;
  srvr.sin_port = htons(lstng_prt);
  bind(srvr_socket,(struct sockaddr *)&srvr, sizeof(srvr));
  listen(srvr_socket, 3);
  addr_len = sizeof(struct sockaddr_in);
  while(1){
      client_socket = accept(srvr_socket, (struct sockaddr *)&client, (socklen_t*)&addr_len); //accept connections
      if(client_socket < 0){
        printf("accept failed\n");
        break;
      }
      if (!RAND_bytes(iv1, sizeof(iv1))) {
        printf("Could not generate IV1");
        break;
      }
      if (!RAND_bytes(iv2, sizeof(iv2))) {
        printf("Could not generate IV2");
        break;
      }

      para.client_socket = client_socket;
      para.dst_ip = dst_ip;
      para.dst_prt = dst_prt;
      para.key = key;
      para.iv1 = iv1;
      para.iv2 = iv2;
      pthread_create(&srvr_thrd, NULL, spwn_srvr, &para);//spawn thread to handle detail of individual connections
  }

  /*join thread after finishing*/
  pthread_join(srvr_thrd, NULL);

}

/*handles individual client connections to pbproxy server*/
void* spwn_srvr(void* context){
    struct c_data* para = (struct c_data*)context;
    int client_socket = para->client_socket;
    int wr_socket;
    struct msgParams msgcp, msgps;
    pthread_t thread0, thread1;
    struct sockaddr_in lcl_srvr;

    sleep(1);

    /*connect with the server*/
    wr_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (wr_socket < 0){
      printf("->Could not create socket\n");
    }

    lcl_srvr.sin_addr.s_addr = inet_addr(para->dst_ip);
    lcl_srvr.sin_family = AF_INET;
    lcl_srvr.sin_port = htons(para->dst_prt);

    if(connect(wr_socket, (struct sockaddr*)&lcl_srvr,sizeof(lcl_srvr))<0){
      puts("->connection error\n");
    }

    /*send ivs to client*/
    write(client_socket, para->iv1, 8);
    write(client_socket, para->iv2, 8);
    msgcp.src_socket = client_socket;
    msgcp.dst_socket = wr_socket;
    msgcp.cryptOp = 0;
    msgcp.key = para->key;
    msgcp.iv = para->iv1;

    /*thread that communicates with client*/
    pthread_create(&thread0, NULL, msgTransfer, &msgcp);

    msgps.src_socket = wr_socket;
    msgps.dst_socket = client_socket;
    msgps.cryptOp = 1;
    msgps.key = para->key;
    msgps.iv = para->iv2;

    /*thread that communicates with the server*/
    pthread_create(&thread1, NULL, msgTransfer, &msgps);
    //printf("new thread again\n");
    pthread_join(thread0, NULL);
    pthread_join(thread1, NULL);

}


/*handles reading from client and sending to server and vice versa
depending on who called it*/
void* msgTransfer(void* context){
  struct msgParams* msgPara = (struct msgParams*)context;
  int src_socket  = msgPara->src_socket;
  int dst_socket = msgPara->dst_socket;
  int cryptOp = msgPara->cryptOp;
  unsigned char* key = msgPara->key;
  //unsigned char tmp[16];
  unsigned char* iv = msgPara->iv;
  int read_size;
  unsigned char msg[BF_SZ];
  unsigned char crypt_text[BF_SZ];
  int len;
  struct ctr_state state;
  AES_KEY aes_key;

    /*initialize fo encryption/decryption*/
    init_ctr(&state, iv);
    AES_set_encrypt_key(key, 128, &aes_key);

    while(1){
        /*read from destination server/client*/
        while((read_size = read(src_socket, msg, BF_SZ)) > 0){

          /*do encryption/decryption*/
          AES_ctr128_encrypt(msg, crypt_text, read_size, &aes_key, state.ivec, state.ecount, &state.num);

          /*write to the destination server/client*/
          if(write(dst_socket, crypt_text, read_size) < 0){
            break;
          }
        }
    }
}


/*handles job of client*/
void client(char* dst_ip, int dst_prt, unsigned char* key){
  int socket_desc;
  struct sockaddr_in srvr_addr;
  unsigned char encryptedtext[BF_SZ];
  unsigned char ip[BF_SZ];
  unsigned char iv1[8], iv2[8];
  int len, read_size;
  pthread_t thread0;
  struct msgParams msgpara;
  struct ctr_state state;
  AES_KEY aes_key;

  /*initialize socket connect to server*/
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc < 0)
  {
    return;
  }
  srvr_addr.sin_addr.s_addr = inet_addr(dst_ip);
  srvr_addr.sin_family = AF_INET;
  srvr_addr.sin_port =  htons(dst_prt);

  if(connect(socket_desc, (struct sockaddr*)&srvr_addr,sizeof(srvr_addr))<0){
    return;
  }

  /*read ivs*/
  if((read_size=read(socket_desc, iv1, 8)) < 0){
    return;
  }
  if((read_size=read(socket_desc, iv2, 8)) < 0){
    return;
  }

  /*initialize parameters for the thread which will handle decryption*/
  msgpara.src_socket = socket_desc;
  msgpara.cryptOp = 0;
  msgpara.key = key;
  msgpara.iv = iv2;

  /*spawn thread to handle reads from pbproxy server*/
  pthread_create(&thread0, NULL, client_recv, &msgpara);

  init_ctr(&state, iv1);
  AES_set_encrypt_key(key, 128, &aes_key);

  while(1){
    /*read from user*/
    while((read_size = read(STDIN_FILENO, ip, BF_SZ)) > 0){
      /*encrypt data*/
      AES_ctr128_encrypt(ip, encryptedtext, read_size, &aes_key, state.ivec, state.ecount, &state.num);

      /*write to pbproxy server*/
      if( write(socket_desc, encryptedtext, read_size) < 0){
        break;
      }
    }
  }
}


/*handles messages received from server*/
void* client_recv(void* context){
  struct msgParams* msgPara = (struct msgParams*)context;
  int socket_desc = msgPara->src_socket;
  int cryptOp = msgPara->cryptOp;
  unsigned char* key = msgPara->key;
  unsigned char* iv = msgPara->iv;
  int read_size, len;
  unsigned char op[BF_SZ], decryptedtext[BF_SZ];
  struct ctr_state state;
  AES_KEY aes_key;

  /*initiliaze*/
  init_ctr(&state, iv);
  AES_set_encrypt_key(key, 128, &aes_key);
  while(1){
    /*read from pbproxy*/
    while((read_size = read(socket_desc, op, BF_SZ)) > 0){

      /*decrypt dmessage from server*/
      AES_ctr128_encrypt(op, decryptedtext, read_size, &aes_key, state.ivec, state.ecount, &state.num);

      /*write to std output*/
      if( write(STDOUT_FILENO, decryptedtext, read_size) < 0){
        break;
      }
    }
  }
}
