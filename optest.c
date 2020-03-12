#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <curl.h>
#include <json.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
int main(int argc,char **argv)
{
     char *URL1 = "http://192.168.0.124:8080/op/Health/network";  /*URLs*/
     char *URL2 = "http://192.168.0.124:8080/op/Health/system";
     char res;int count;
     if (argc < 2 || argc > 2)
     {
             printf("Enter two arguments as binary + network_restart (or) reboot \n");
             exit(1);
     }
     char str[2][20] = {"network_restart","reboot"}; /* 2D array decleration default strings */
     int i,j;
     /* To findout network connection */
     int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
     struct sockaddr_in addr = {AF_INET, htons(80), inet_addr("192.168.0.121")}; /*port number & IP address of GW */
     struct timeval timeout;
     timeout.tv_sec = 1;
     timeout.tv_usec = 0;
     setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
     setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
     if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == 0)
     {
      printf("\n................................Network is fine in the gateway...................................\n");

      for (i=0;i<2;i++)
      {
          if (strcmp(str[i],argv[1])==0)
          {
                 j=i;
               switch(j)
               {
                    case 0 : /*if network_restart*/
               {
                      printf("\n....................................sending request to the server..................................\n");
                     // printf("\n-----------------------------------------------------------------------------------------------------\n");
                       CURL *curl;
                       CURLcode res;
                       char *response =malloc(55*sizeof(char));
                       curl = curl_easy_init();
                       if(curl)
                       {
                              curl_easy_setopt(curl, CURLOPT_URL,URL1);
                              /* example.com is redirected, so we tell libcurl to follow redirection */
                              curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                              /* complete within 40 seconds */
                              curl_easy_setopt(curl, CURLOPT_TIMEOUT, 40L);
                              /* Perform the request, res will get the return code */
                               res = curl_easy_perform(curl);
                               if(res != CURLE_OK) /*Check for errors */
                        {
                                   /* write log message*/
                              openlog("RasPi", LOG_PID | LOG_NDELAY, LOG_USER);
                              syslog(LOG_ERR,"The error is from server side: %m");
                              closelog();
                              return 0;
                         }
                         if(res == CURLE_OK) /* if response received */
                         {
                           //    sleep(1);
                               printf("\n---------------------------------------------------------------------------------------------------\n");
                               printf("\n................................***....response received...****....................................\n");
                               sleep(1);
                               printf("\n----------------------------------------------------------------------------------------------------\n");
                               printf(" \n........................***...network going to restart...***.......................................\n");
                               printf("-------------------------------------------------------------------------------------\n");
                               system("/etc/init.d/network restart"); /*network is restarted*/
                               printf("network restart\n");                         
                                        
                                  /*write log message*/
                               openlog("RasPi",LOG_PID | LOG_NDELAY,LOG_USER);
                               syslog(LOG_ERR,"Network  is restarting :%m");
                               closelog();
                               return 0;
                           }
                     }
              }
                              case 1 :  /* if reboot */
                                    printf("\n...............................sending request to the server.....................................\n");
                                 //   printf("\n---------------------------------------------------------------------------------------------------\n");
                                    CURL *curl;
                                    CURLcode res;
                                    char *response =malloc(55*sizeof(char));
                                    curl = curl_easy_init();
                                    if(curl)
                                    {
                                          curl_easy_setopt(curl, CURLOPT_URL, URL2);
                                          /* example.com is redirected, so we tell libcurl to follow redirection */
                                          curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                                          /* complete within 40 seconds */
                                          curl_easy_setopt(curl, CURLOPT_TIMEOUT, 40L);
                                           /* Perform the request, res will get the return code */
                                           res = curl_easy_perform(curl);
                                           if(res != CURLE_OK) /* check for errors */
                                           {     /* write log message */
                                                 openlog("RasPi",LOG_PID | LOG_NDELAY,LOG_USER);
                                                 syslog(LOG_ERR,"The error from serverside:%m");
                                                 closelog();
                                                  return 0;
                                            }
                                            if(res == CURLE_OK) /* if response received */
                                            {
                                                     printf("\n-----------------------------------------------------------------------------------------------\n");
                                                     printf("\n....*****..................................response received...*****...........................\n");
                                            //         sleep(1);
                                                     printf("\n-----------------------------------------------------------------------------------------------\n");
                                                     printf("\n.....................................***....rebooting the gateway.....*****...................\n");
                                              //       printf("\n----------------------------------------------------------------------------------------------\n");
                                                     system("reboot"); /*system going to reboot */
                                                      
                                                          /* write log message */
                                                     openlog("RasPi",LOG_PID | LOG_NDELAY,LOG_USER);
                                                     syslog(LOG_ERR,"The gateway is rebooting:%m");
                                                     closelog();
                                                     break;
                                               }
                                       }

              for(i=0;i<2;i++)
              {
                         
              if (strcmp(str[i],argv[1])!=0) /*comparison of default strings& commandline string*/
                {
                     count++;
                }
                }
          if(count==2)
          {
              goto label;
          }
 
               label:
                      default:
                                 {
                                          printf("\n...command is invalid:give binary+ network_restart(or)reboot\n");
                                         return 0;
                                }
                           }
                    }
           }
   
    }
     else
        {
                   /* if there is no network */
                  printf("\n No network in the gateway\n");
                  //system("/etc/int.d/restart");
                   /* write log message */
                   openlog("RasPi",LOG_PID | LOG_NDELAY,LOG_USER);
                   syslog(LOG_CRIT,"There is no network in gateway:%m");
                   closelog();
                   return 0;
        }
}

