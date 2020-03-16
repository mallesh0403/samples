/****************************************************************************************************/
/**************************                   Include files                      ********************/
/****************************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>
#include <json.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <openssl/sha.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <pthread.h>
#include <syslog.h>
#include <libconfig.h>
#include <config.h>
#include <ugpio.h>
#include <stdarg.h>
#include <ugpio-internal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/shm.h>

/****************************************************************************************************/
/**************************            Macro Definitions            *********************************/
/****************************************************************************************************/

#define STATUS_OK 1
#define IS_STATUS_OK(v) (v == STATUS_OK)
#define PACKETSIZE 64

#define GW_TAG "[CONFIG]"
#define NW_TAG "[NETWORK]"
#define UART_TAG "[UART]"
#define HEALTH_TAG "[HEALTH]"
#define PING_TAG "[PING]"
#define GW_CONFIG_PATH "/etc/lizard/gateway.conf"

/****************************************************************************************************/
/*************************         Local Function Prototypes    *************************************/
/*Two threads running 
        A.Network Monitor
        B.Uart Monitor

A) Function list of inside Network Monitor Thread.
 1) check_dhcp_availablity
 2) update_local_nwif_state
 3) eth0_state
 4) brlan_state
 5) eth1_stateint ping(char *adress)
 6) check_local_network
 7) check_internet_connection
 8) align_with_servertime
 9) set_with_server_time

B) Function list of inside UART Monitor Thread.
 1) read_uart
 2) splitwords
 3) invoke_saveV1_url
 4) invoke_getV1_url
 5) hit_endpoint_url
 6) get_machttp://test4.lizardmonitoring.com:8080/app/reading/saveV1?netnum=12ed5cc&password=V0017013EA69F10E5A5DFBB95ADF1B4B5C9DC0BE978D&smac=00158d000032e6ae&gmac=00158d00047824cb&seq=3264&temp=2950&bat=2877&sensortime=2920e7&status=132&rejoins=209&lqi=180&f3=1194&f4=2038&slqi=148&jversion=1468&luc=120401b7&gatewaytime=5d503bd3
 7) checksum
 8) server_response_callback
 9) dec_to_hex
 10) hex_to_dec
 11) json_parse
****************************************************************************************************/

void splitwords(char *str);
void invoke_saveV1_url(char[][120]);
void invoke_getV1_url(char[][120]);
char *hit_endpoint_url(char *, const char *);
char *get_mac(char *);
void checksum(char *ptr);
char *dec_to_hex(long long decimalnum);
long long hex_to_dec(const char *hex);
int json_parse(json_object *);
static size_t server_response_callback(void *, size_t, size_t, void *);

void *health_monitor(void *vargp);
void *network_monitor(void *vargp);
void update_local_nwif_state(char *);
void eth0_state(void);
void brlan_state(void);
void eth1_state(void);
void usb_state(void);
int check_dhcp_availablity(void);
int check_local_network(void);
int check_internet_connection(void);
int align_with_servertime(void);
int set_with_server_time(char *);
void *uart_monitor(void *vargp);
void read_uart(void);
void wsn_up(void);
int ping(const char *adress);
unsigned short ping_checksum(void *b, int len);
void error_log(char *, char *, ...);
void info_log(char *, char *, ...);

/******************************************************************************************************/
/***************************            Global Variables            ***********************************/
/******************************************************************************************************/

char __sensor_parms[16][40] = {"netnum=", "password=", "smac=", "gmac=", "seq=", "temp=", "bat=", "sensortime=", "status=", "rejoins=", "lqi=", "f3=", "f4=", "slqi=", "jversion=", "luc="};

char *__get_parms[9] = {"netnum=", "gmac=", "seq=", "gtime=", "jversion=", "panid=", "gluc=", "chn=", "count="};

char __split_strings[20][120];

static int __cnt = 0;

char __uc_mac[60] = "", __gateway_time_stamp[30] = "";

int __HIGH = 1, __LOW = 0, __hbt_initial = 0, __json_value = 0, __pre_json_value = 1, __var_value;

char __hex_value[45] = "", __hardware_net_id[] = "eth0", __cell_modem_net_id[] = "eth1",__usb_net_id[]="usb0";

bool __is_nw_avail = false;

bool __is_uart_avail = false;

bool __is_first_interface = false;

bool __is_second_interface = false;

bool __is_usb_interface = false;

int __pid = -1;

int __ping_cnt = 1;

/* networking global variables */

char __eth0_range[10] = "", __brlan_range[10] = "", __eth1_range[10] = "";

pthread_t __nw_thread_id, __uart_thread_id, __health_thread_id;

bool __is_time_sync = false;

CURLcode __curl_response;
CURLSH *__ssl_session_id;

/* reading from gateway config file */

const char *__ether_state, *__cmodem_state, *__brlan, *__host, *__time_url, *__port, *__avers, *__get_url, *__save_url, *__salt, *__green_stat;

int __RESET, __YELLOW, __RED, __GREEN, __log_level;

int __nw_thread_sleep, __uart_thread_sleep, __health_thread_sleep;

/********************************************************************************************************/
/**********************************        Structure Definition               ***************************/
/********************************************************************************************************/

struct server_response
{
    char *memory;
    size_t size;
};
struct server_response __response_chunk;

struct _health
{
    time_t curtime;
    bool inet_status;
    bool uart_status;
    bool first_interface_status;
    bool second_interface_status;
    bool usb_status;
} __health;

struct protoent *__proto = NULL;

struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

int main()
{
    FILE *fptr;

    // represents a configuration
    config_t cfg;

    //represents a configuration setting
    config_setting_t *gateway;

    // initializes the config_t structure pointed to by config.
    config_init(&cfg);

    //open a file
    fptr = fopen(GW_CONFIG_PATH, "r");

    if (fptr == NULL)
    {
        error_log(GW_TAG, "There is NO Config file in gateway");
        exit(1);
    }

    info_log(GW_TAG, "Successfully reading the gateway Configuration file");

    //This function reads and parses a configuration from the given stream into the configuration object config.
    if (!config_read(&cfg, fptr))
    {
        info_log(GW_TAG, "Data format is invalid in config file");
        exit(1);
    }

    //These functions look up the value of the setting in the configuration config specified by the path path.
    if (config_lookup_string(&cfg, "eth0_operstate", &__ether_state))
    {
        info_log(GW_TAG, "Successfully reading the eth0 operstate");
    }
    else
    {
        info_log(GW_TAG, "eth0 operstate path is Not available");
    }

    if (config_lookup_string(&cfg, "eth1_operstate", &__cmodem_state))
    {
        info_log(GW_TAG, "Successfully reading the eth1 operstate");
    }
    else
    {
        info_log(GW_TAG, "eth1 operstate path is Not available");
    }

    if (config_lookup_string(&cfg, "brlan_operstate", &__brlan))
    {
        info_log(GW_TAG, "Successfully reading the brlan operstate");
    }
    else
    {
        info_log(GW_TAG, "brlan operstate path is Not available");
    }

    if (config_lookup_string(&cfg, "icmp_host", &__host))
    {
        info_log(GW_TAG, "Successfully reading the icmp host");
    }
    else
    {
        info_log(GW_TAG, "icmp_host path is not available");
    }

    if (config_lookup_string(&cfg, "time_server_url", &__time_url))
    {
        info_log(GW_TAG, "Successfully reading the time_server_url");
    }
    else
    {
        info_log(GW_TAG, "The time_server_url is not available");
    }

    if (config_lookup_string(&cfg, "uart_port", &__port))
    {
        info_log(GW_TAG, "Successfully reading the uart_port");
    }

    else
    {
        info_log(GW_TAG, "The uart_port is not available");
    }

    if (config_lookup_string(&cfg, "aversion", &__avers))
    {
        info_log(GW_TAG, "Successfully reading the aversion");
    }
    else
    {
        info_log(GW_TAG, "The aversion is not available");
    }

    if (config_lookup_string(&cfg, "getV1_url", &__get_url))
    {
        info_log(GW_TAG, "Successfully reading the getV1_url");
    }
    else
    {
        info_log(GW_TAG, "The getV1_url is not available");
    }

    if (config_lookup_string(&cfg, "saveV1_url", &__save_url))
    {
        info_log(GW_TAG, "Successfully reading the saveV1_url");
    }
    else
    {
        info_log(GW_TAG, "The saveV1_url is not available");
    }
    if (config_lookup_int(&cfg, "reset_pin", &__RESET))
    {
        info_log(GW_TAG, "Successfully reading the reset_pin");
    }
    else
    {
        info_log(GW_TAG, "The reset_pin is not available");
    }

    if (config_lookup_int(&cfg, "yellow_led", &__YELLOW))
    {
        info_log(GW_TAG, "Successfully reading the yellow_led");
    }
    else
    {
        info_log(GW_TAG, "The yellow_led is not available");
    }

    if (config_lookup_int(&cfg, "red_led", &__RED))
    {
        info_log(GW_TAG, "Successfully reading the red_led");
    }
    else
    {
        info_log(GW_TAG, "The red_led is not available");
    }

    if (config_lookup_int(&cfg, "green_led", &__GREEN))
    {
        info_log(GW_TAG, "Successfully reading the green_led");
    }
    else
    {
        info_log(GW_TAG, "The green_led is not available");
    }

    if (config_lookup_string(&cfg, "salt_key", &__salt))
    {
        info_log(GW_TAG, "Successfully reading the salt_key");
    }
    else
    {
        info_log(GW_TAG, "The salt_key is not available");
    }
    if (config_lookup_int(&cfg, "conf_log_level", &__log_level))
    {

        info_log(GW_TAG, "Successfully reading the log_level");
    }
    else
    {
        info_log(GW_TAG, "The conf_log_level is not available");
    }

    if (config_lookup_int(&cfg, "nw_monitor_sleep_dur", &__nw_thread_sleep))
    {
        info_log(GW_TAG, "Successfully reading the nw_thread_sleep");
    }
    else
    {
        info_log(GW_TAG, "The green_led is not available");
    }
    if (config_lookup_int(&cfg, "uart_monitor_sleep_dur", &__uart_thread_sleep))
    {
        info_log(GW_TAG, "Successfully reading the UART_thread_sleep");
    }
    else
    {
        info_log(GW_TAG, "The UART_thread_sleep is not available");
    }
    if (config_lookup_int(&cfg, "health_monitor_sleep_dur", &__health_thread_sleep))
    {
        info_log(GW_TAG, "Successfully reading the health_thread_sleep");
    }
    else
    {
        info_log(GW_TAG, "The health_thread_sleep is not available");
    }

    if (config_lookup_string(&cfg, "green_led_path", &__green_stat))
    {
        info_log(GW_TAG, "Successfully reading the green led path");
    }
    else
    {
        info_log(GW_TAG, "The green led path is not available");
    }

    /* GPIO pins direction and values */
    gpio_request(__RESET, GPIOF_DIR_OUT);  //request gpio-25 as out
    gpio_request(__YELLOW, GPIOF_DIR_OUT); //request gpio-17 as out
    gpio_request(__GREEN, GPIOF_DIR_OUT);  //request gpio-23  as out
    gpio_request(__RED, GPIOF_DIR_OUT);    //request gpio-27  as out

    gpio_direction_output(__RESET, __LOW);  //reset pin initially LOW state
    gpio_direction_output(__RED, __LOW);    //red-led initially ON  (initially ON&OFF to get out red,yellow,green from half active states)
    gpio_direction_output(__YELLOW, __LOW); //yellow-led initally ON
    gpio_direction_output(__GREEN, __LOW);  //green-led initially ON

    gpio_set_value(__YELLOW, __HIGH); //yellow-led OFF
    gpio_set_value(__GREEN, __HIGH);  //green-led OFF

    curl_global_init(CURL_GLOBAL_ALL);

    __ssl_session_id = curl_share_init();

    curl_share_setopt(__ssl_session_id, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);

    info_log(NW_TAG, "Network thread was started");

    //start network monitor thread
    pthread_create(&__nw_thread_id, NULL, network_monitor, "network_thread \n");

    //Start health_monitor thread.
    pthread_create(&__health_thread_id, NULL, health_monitor, "health_thread \n");

    while (1)
        ;

    gpio_free(__RESET);  //free reset pin
    gpio_free(__YELLOW); //free yellow led
    gpio_free(__RED);    //free red led
    gpio_free(__GREEN);  //free green led

    fclose(fptr); //close file descriptorrm

    return 0;
}

/**********************************************************************************
*
* NAME: network_monitor
* DESCRIPTION:
* This function monitoring the network availability continuously
* PARAMETERS:      Name           RW        Usage
*                  *vargp         R                               
*
***********************************************************************************/
void *network_monitor(void *vargp)
{
    static long counter = 0;
    while (1)
    {
        int is_time_updated;
        if (check_dhcp_availablity() == STATUS_OK) //Network is available
        {
            __is_nw_avail = true;

            //Sync time only once. This variable remains true forever after it is set
            if (__is_time_sync == false)
            {
                gpio_set_value(__YELLOW, __LOW); //yellow ON
                is_time_updated = align_with_servertime();

                if (IS_STATUS_OK(is_time_updated))
                {
                    wsn_up(); //RESET the WSN

                    __is_time_sync = true;

                    info_log(UART_TAG, "[network_monitor]:UART thread was started");

                    pthread_create(&__uart_thread_id, NULL, uart_monitor, "uart_thread "); //Start UART monitor thread.
                }
            }
        }
        else
        {
            __is_nw_avail = false;
        }
        sleep(__nw_thread_sleep);
    }
    return NULL;
}
/****************************************************************************
*
* NAME: check_dhcp_availablity
* DESCRIPTION:
* This function check the local and external network status
*
*RETURN:
* int                           
*
*****************************************************************************/
int check_dhcp_availablity(void)
{
    __eth0_range[0] = '\0', __eth1_range[0] = '\0';

    FILE *green_fp1;

    char green_value[2]="";
    int dhcp_val=0;

    struct ifaddrs *addrs, *tmp;

    getifaddrs(&addrs);
    tmp = addrs;
    if ((green_fp1 = fopen(__green_stat, "r")) == NULL)
    {
        error_log(NW_TAG, "There is NO gpio23 green file path");
        exit(1);
    }

    fgets(green_value, 2, green_fp1);
    int green_led_status = atoi(green_value);
    //info_log(NW_TAG, "[check_dhcp_availablity]:Available Network interfaces");
    if ((void *)tmp != NULL)
    {
        while (tmp)
        {
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
            {
                //Updates global variables based on network interface state
               /* if(!(strcmp(tmp->ifa_name,"usb0")))
                {
                     // info_log(NW_TAG, "[check_dhcp_availablity]:Local dhcp ok when usb connected");
                      dhcp_val=1; 
                      __is_usb_interface=true;
                }*/
                   update_local_nwif_state(tmp->ifa_name);   
            }
            tmp = tmp->ifa_next;
        }
    }
    freeifaddrs(addrs);
    fclose(green_fp1);

    dhcp_val = check_local_network(); //If dhcp_val == 1, local network is available

    if (dhcp_val == 1)
    {

        info_log(NW_TAG, "[check_network_availablity]:Local DHCP OK");

        gpio_set_value(__RED, __HIGH); //RED led OFF if local DHCP OK

        int icmp_val = check_internet_connection();

        if (icmp_val == 1)
        {
            info_log(NW_TAG, "[check_network_availablity]:Connection established with outside world");
            if (green_led_status == 1) //green led off state
            {
                gpio_set_value(__YELLOW, __LOW); //YELLOW LED ON
            }
            return 1; //success
        }

        else
        {
            info_log(NW_TAG, "[check_network_availablity]:No connection with outside world");
            gpio_set_value(__GREEN, __HIGH); //Green off
            gpio_set_value(__YELLOW, __LOW); //YELLOW LED ON
            return 2;                        //No network connection
        }
    }

    else
    {
        info_log(NW_TAG, "[check_network_availablity]:Nothing connected to gateway");
        gpio_set_value(__YELLOW, __HIGH); //yellow off
        gpio_set_value(__GREEN, __HIGH);  //Green off
        gpio_set_value(__RED, __LOW);     //Red ON
        return 3;                         //No local DHCP network
    }
}
/*************************************************************************************
*
* NAME: update_local_nwif_state
* DESCRIPTION:
* This function updates the available interfaces
* PARAMETERS:      Name           RW        Usage
*                  *nw_interface   R        reading the network interface names                     
*
**************************************************************************************/
void update_local_nwif_state(char *nw_interface)
{
    info_log(NW_TAG, "[update_local_nwif_state]: %s", nw_interface);

    if (!(strcmp(nw_interface, "eth0")))
    {
        eth0_state();
    }
    else if (!(strcmp(nw_interface, "br-lan")))
    {
        brlan_state();
    }
    else if (!(strcmp(nw_interface, "eth1")))
    {
        eth1_state();
    }
    else if(!(strcmp(nw_interface, "usb0")))
    {
        usb_state();
    }
}
/*******************************************************************************
*
* NAME: eth0_state
* DESCRIPTION:
* This function check the eth0 interface state                 
*
********************************************************************************/
void eth0_state(void)
{
    FILE *fp;
    char ptr[7] = "";
    int i = 0;

    fp = fopen(__ether_state, "r");

    fgets(ptr, 7, fp);

    for (i = 0; i < strlen(ptr); i++)
    {
        if (ptr[i] != '\n')
            __eth0_range[i] = ptr[i];
    }
    __eth0_range[i - 1] = '\0';

    info_log(NW_TAG, "[eth0_state]:eth0_state is %s", __eth0_range);

    fclose(fp);
}
/***********************************************************************************
*
* NAME: brlan_state
* DESCRIPTION:
* This function check eth0 interface state                      
*
************************************************************************************/
void brlan_state(void)
{
    FILE *fp1;
    char ptr1[7];
    int i = 0;

    fp1 = fopen(__brlan, "r");

    fgets(ptr1, 7, fp1);

    for (i = 0; i < strlen(ptr1); i++)
    {
        if (ptr1[i] != '\n')
            __brlan_range[i] = ptr1[i];
    }
    __brlan_range[i - 1] = '\0';

    info_log(NW_TAG, "[brlan_sate]:br-lan_state is %s", __brlan_range);
    fclose(fp1);
}
/****************************************************************************
*
* NAME: eth1_state
* DESCRIPTION:
* This function check the eth1 interface state
*                   
*****************************************************************************/

void eth1_state(void)
{
    FILE *fp2;
    char ptr2[7] = "";
    int i = 0;

    fp2 = fopen(__cmodem_state, "r");

    fgets(ptr2, 7, fp2);

    for (i = 0; i < strlen(ptr2); i++)
    {
        if (ptr2[i] != '\n')
            __eth1_range[i] = ptr2[i];
    }
    __eth1_range[i - 1] = '\0';

    info_log(NW_TAG, "[eth1_state]:eth1_state is %s\n", __eth1_range);
    fclose(fp2);
}
void usb_state(void)
{
  // dhcp_val=1;
   __is_usb_interface=true;
}

/*******************************************************************************
*
* NAME: check_local_network
* DESCRIPTION:
* This function check the local network interface states.
* RETURN:
*  int                                 
*
********************************************************************************/

int check_local_network(void)
{
    if ((__eth0_range[0] == 'u') && (__eth1_range[0] == 'u'))

    {
        info_log(NW_TAG, "[check_local_network]:Both eth0 & eth1 are in UP state DHCP-OK");
        __is_first_interface = true;
        __is_second_interface = true;
        return 1;
    }

    else if (((__eth0_range[0] == 'u') && (__eth1_range[0] == 'd')) || ((__eth0_range[0] == 'u') && (__eth1_range[0] == '\0')))
    {
        info_log(NW_TAG, "[check_local_network]:Only eth0 UP state DHCP-OK");
        __is_first_interface = true;
        return 1;
    }
    else if (((__eth0_range[0] == 'd') && (__eth1_range[0] == 'u')) || ((__eth0_range[0] == '\0') && (__eth1_range[0] == 'u')))
    {
        info_log(NW_TAG, "[check_local_network]:Only eth1 UP state DHCP-OK");
        __is_second_interface = true;
        return 1;
    }
    else if (__is_usb_interface == true)
    {
         info_log(NW_TAG, "[check_local_network]:Only usb0 state DHCP-OK");
         return 1;
    }
   else
    {
        info_log(NW_TAG, "[check_local_network]:Both eth0 & eth1 & usb0 are in DOWN state NO-DHCP (RED-led-ON)");
        return 0;
    }
}

/************************************************************************************
*
* NAME: check_internet_connection
* DESCRIPTION:
* This function check the internet connection with outside world.
*
* RETURN:
*  int                 
*************************************************************************************/

int check_internet_connection(void)
{

    if (ping(__host) == 0)
    {
        info_log(NW_TAG, "[check_internet_connection]:Internet connection is OK");
        return 1;
    }
    else
    {
        info_log(NW_TAG, "[check_internet_connection]:No Internet connection");
        return 0;
    }
}

/***********************************************************************************
*
* NAME: align_with_servertime
* DESCRIPTION:
* This function hits the time url
* PARAMETERS:      Name           RW        Usage
*                  *vargp         R                            
* RETURN:
* int                

************************************************************************************/

int align_with_servertime(void)
{

    CURL *curl_handle;
    CURLcode res;

    struct server_response chunk;

    chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);

    /* init the curl session */
    curl_handle = curl_easy_init();

    if (curl_handle)
    {
        curl_easy_setopt(curl_handle, CURLOPT_SHARE, __ssl_session_id);

        info_log(NW_TAG, "[align_with_servertime]:seesion id used: %p", __ssl_session_id);
        /* specify URL to get */
        curl_easy_setopt(curl_handle, CURLOPT_URL, __time_url);

        /* send all data to this function  */
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, server_response_callback);

        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 60L);

        res = curl_easy_perform(curl_handle);
        /* check for errors */
        if (res != CURLE_OK)
        {
            error_log(NW_TAG, "[align_with_servertime]: curl_easy_perform() failed: %s", curl_easy_strerror(res));
            curl_easy_cleanup(curl_handle);
            free(chunk.memory);

            return 2; //Curl failed
        }
        else
        {
            /* Now, our chunk.memory points to a memory block that is chunk.size */
            info_log(NW_TAG, "[align_with_servertime]: Getting Time from Server: %s", chunk.memory);
            set_with_server_time(chunk.memory);

            /* cleanup curl stuff */
            curl_easy_cleanup(curl_handle);

            free(chunk.memory);
            return STATUS_OK;
        }
    }
}
/************************************************************************************
*
* NAME: server_response_callback
* DESCRIPTION:
* This function set callback for writing received data
* PARAMETERS:      Name           RW        Usage
*                  *contents      R
*                   size          R         Read the size.
*                   nmemd         R         Read the number of bytes.
*                   *userp   
*
*************************************************************************************/

static size_t server_response_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct server_response *mem = (struct server_response *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);

    if (ptr == NULL)
    {
        /* out of memory! */
        info_log(NW_TAG, "[server_response_callback]:Not enough memory (realloc returned NULL)");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}
/***************************************************************************************
*
* NAME: set_with_server_time
* DESCRIPTION:
* This function getting the time from remote server and set to local gateway time.
* PARAMETERS:      Name           RW        Usage
*                  *ptr            R        read the server time 
* RETURN:
* int                 
***************************************************************************************/

int set_with_server_time(char *ptr)
{
    long long int val = atoi(ptr); //string to integer
    struct timeval nmr;
    int rc;
    nmr.tv_sec = val;
    nmr.tv_usec = 0;
    rc = settimeofday(&nmr, NULL);

    if (rc == 0)
    {
        info_log(NW_TAG, "[set_with_server_time]: Settimeofday is successfull");
        info_log(NW_TAG, "[set_with_server_time]: Gateway time was synchronized with server time");

        __is_time_sync = true;
        return 1;
    }
    else
    {
        info_log(NW_TAG, "[set_with_server_time]:Settimeofday is failed");
        info_log(NW_TAG, "[set_with_server_time]:Gateway time was not sync with server time");

        __is_time_sync = false;
        return 0;
    }
}
/************************************************************************************
*
* NAME: uart_monitor
* DESCRIPTION:
* This function monitor the uart
* PARAMETERS:      Name           RW        Usage
*                  *vargp          R        read the argument from uart monitor thread 
*                
*************************************************************************************/

void *uart_monitor(void *vargp)
{
    static long counter = 0;
    // sleep(1);

    while (1)
    {
        read_uart();

        sleep(__uart_thread_sleep);
    }

    return NULL;
}

/**********************************************************************************************************/
/*******************************    UART Connection Settings             **********************************/
/**********************************************************************************************************/
/********************************************************************************************************** 
                  
                  Bits per second: 115200 (this is the default for all modes of operation)
                  Data bits: 8
                  Parity: None
                  Stop bits: 1
                  Flow control: None (no flow control)
***********************************************************************************************************/
void read_uart(void)
{
    int i, fd;
    char buff[350] = "";
    fd = open(__port, O_RDWR | O_NOCTTY);

    if (fd == -1)
    {
        error_log(UART_TAG, "[READ_UART]:Error! in Opening %s", __port);
        exit(1);
    }

    info_log(UART_TAG, "[READ_UART]:Successfully opened %s  UART port", __port);

    struct termios SerialPortSettings;

    tcgetattr(fd, &SerialPortSettings);

    cfsetispeed(&SerialPortSettings, B115200);
    cfsetospeed(&SerialPortSettings, B115200);

    SerialPortSettings.c_cflag &= ~PARENB;
    SerialPortSettings.c_cflag |= PARENB;
    SerialPortSettings.c_cflag &= ~PARENB;

    SerialPortSettings.c_cflag &= ~CSTOPB;
    SerialPortSettings.c_cflag &= ~CSIZE;
    SerialPortSettings.c_cflag |= CS8;

    SerialPortSettings.c_cflag &= ~CRTSCTS;
    SerialPortSettings.c_cflag |= CREAD | CLOCAL;
    SerialPortSettings.c_iflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    tcsetattr(fd, TCSANOW, &SerialPortSettings);

    if ((tcsetattr(fd, TCSANOW, &SerialPortSettings)) != 0)
    {
        error_log(UART_TAG, "[READ_UART]:ERROR ! in Setting attributes");
    }
    else
    {
        info_log(UART_TAG, "[READ_UART]:BAUD_RATE = 115200, StopBits = 1, Parity = none ");
    }

    tcflush(fd, TCIFLUSH);

    while (1)
    {

        for (i = 0; i < 350; i++)
        {
            buff[i] = '\0';
        }

        int b = read(fd, buff, 350);

        info_log(UART_TAG, "[READ_UART]: Reading data from uart: %s \n", buff);

        if (__is_nw_avail == false)
        {
            info_log(UART_TAG, "[READ_UART]:Network NOT available.Data not sending to server (GREEN-led-OFF)");
        }
        else
        {
            if (b > 0)
            {
                if (b == 1 && buff[0] == '\n')
                {
                    info_log(UART_TAG, "[READ_UART]: Empty line is arrived");
                }
                else
                {
                    __is_uart_avail = true;

                    info_log(UART_TAG, "[READ_UART]: Formatting data and sending to server");
                    splitwords(buff);
                }
            }
            else
            {
                info_log(UART_TAG, "[READ_UART]:Datasize is 0. No data is received from uart now");
            }
        }
    }

    close(fd);
}
/********************************************************************************************************
* NAME: splitwords
* DESCRIPTION:
* This function split the UART data form into words based on comma.
* After splited UART data first time it will fetch the HBTO data only and then after it will fetch the symantanously.
* 
* PARAMETERS:      Name            RW              Usage
                   *str            R               Read the UART data and store into character pointer variable. 
* RETURN: 
* void
***********************************************************************************************************/

void splitwords(char *str)
{

    char ptr[2][20] = {"HBT0", "DAT0"};
    int i = 0, j = 0, len = 0;
    __cnt = 0;
    for (i = 0; i <= (strlen(str)); i++)
    {
        // if comma or NULL found, assign NULL into __split_strings[__cnt]
        if (str[i] == ',' || str[i] == '\n')
        {
            __split_strings[__cnt][j] = '\0';
            __cnt++;
            j = 0;
        }
        else
        {
            __split_strings[__cnt][j] = str[i];

            j++;
        }
    }

    info_log(UART_TAG, "[splitwords]:Original incoming data is:\n %s \n", str);
    info_log(UART_TAG, "[splitwords]:Data after split by comma(,)");

    for (i = 0; i < __cnt; i++)
    {
        info_log(UART_TAG, "[splitwords]: %s", __split_strings[i]);
    }

    if (((strcmp(__split_strings[0], ptr[0])) == 0) && (__hbt_initial == 0))
    {
        invoke_getV1_url(__split_strings);
        __hbt_initial++;
    }

    else
    {
        if (__hbt_initial == 1)
        {
            for (i = 0; i < 2; i++)
            {
                if ((strcmp(__split_strings[0], ptr[i])) == 0)
                {
                    ++len;
                    switch (len)
                    {

                    case 1:
                        invoke_getV1_url(__split_strings);
                        break;

                    case 2:
                        invoke_saveV1_url(__split_strings);
                        break;

                    default:
                        info_log(UART_TAG, "[splitwords]: NO data availiable");
                    }
                }
                ++len;
            }
        }
    }
}

/**************************************************************************************************************
*
* NAME: invoke_getV1_url
* DESCRIPTION:
* This function fetch the __get_parms field with HBTO fields.
* After that based on server response send the GateWay cmac.
* PARAMETERS:      Name            RW       Usage
*                 split_strings     R       Read the DAT0 data after splited words based on comma and stored into double array 
                                           string variable.
* RETURN:
* void
*
****************************************************************************************************************/
void invoke_getV1_url(char split_strings[][120])
{
    int l = 0, k = 1, i;
    int hbt = 0;
    __cnt = __cnt - 1;
    char getv1_buff2[450] = "", dest[100] = "", src[100] = "", *mac;
    strcpy(__gateway_time_stamp, split_strings[4]);

    for (l = 0; l < __cnt; l++)
    {
        strcat(dest, __get_parms[l]);
        strcat(src, split_strings[k++]);
        strcat(dest, src);

        if (l != __cnt - 1)
        {
            strcat(dest, "&");
        }

        else
        {
            //  strcat(dest,"&");
        }

        strcat(getv1_buff2, dest);
        dest[0] = '\0';
        src[0] = '\0';
    }
    strcat(getv1_buff2, "&aversion="); //adding aversion key to getV1 call
    strcat(getv1_buff2, __avers);      //adding aversion vale to getV1 call

    char *server_res_getV1 = hit_endpoint_url(getv1_buff2, __get_url);
    info_log(UART_TAG, "[invoke_getV1_url]:Serverresponse from getV1: %s", server_res_getV1);

    if (__curl_response != CURLE_OK)
    {
        error_log(UART_TAG, "[invoke_getV1_url]: curl_easy_perform()failed: %s", curl_easy_strerror(__curl_response));
        error_log(UART_TAG, "[invoke_getV1_url]:Server NOT seen.(GREEN-led-OFF) & (YELLOW-led-ON) ");
        gpio_set_value(__GREEN, __HIGH); //green OFF
        gpio_set_value(__YELLOW, __LOW); //yellow ON
    }
    else
    {

        char *str = strstr(server_res_getV1, "sendcmac");

        if (str != NULL)
        {
            info_log(UART_TAG, "[invoke_getV1_url]: Auto provision feature is generated");

            json_object *jobj = json_tokener_parse(__response_chunk.memory);
            __json_value = json_parse(jobj);

            if (__json_value == __pre_json_value)
            {

                if ((__eth0_range[0] == 'u') && (__eth1_range[0] == 'u'))

                {
                    info_log(UART_TAG, "[invoke_getV1_url]:Both eth0 & eth1 are in UP state");

                    mac = get_mac(__hardware_net_id);
                }

                else if (((__eth0_range[0] == 'u') && (__eth1_range[0] == 'd')) || ((__eth0_range[0] == 'u') && (__eth1_range[0] == '\0')))
                {
                    info_log(UART_TAG, "[invoke_getV1_url]:Only eth0 is UP state");
                    mac = get_mac(__hardware_net_id);
                }
                else if (((__eth0_range[0] == 'd') && (__eth1_range[0] == 'u')) || ((__eth1_range[0] == '\0') && (__eth1_range[0] == 'u')))
                {
                    info_log(UART_TAG, "[invoke_getV1_url]:Only eth1 is UP state");

                    mac = get_mac(__cell_modem_net_id);
                }
                else if (__is_usb_interface == true)
                {
                     info_log(UART_TAG, "[invoke_getV1_url]:Only usb0 is UP state");
                     mac = get_mac(__usb_net_id);
                }
                else
                {
                    info_log(UART_TAG, "[invoke_getV1_url]:Both eth0 & eth1 & usb0 are in DOWN state");
                }
                long long mac_deci, salt_deci, xor_salt_cmac;

                salt_deci = hex_to_dec(__salt);
                mac_deci = hex_to_dec(mac);

                xor_salt_cmac = salt_deci ^ mac_deci;

                char *r = dec_to_hex(xor_salt_cmac);
                char gateway_mac[] = "&cmac=";

                strcat(getv1_buff2, gateway_mac);
                strcat(getv1_buff2, r);

                info_log(UART_TAG, "[invoke_getV1_url]:After adding cmac to url :%s", getv1_buff2);

                char *auto_provision_res = hit_endpoint_url(getv1_buff2, __get_url);

                info_log(UART_TAG, "[invoke_getV1_url]:Auto provision response from server side: %s", auto_provision_res);
                info_log(UART_TAG, "[invoke_getV1_url]:Auto provision feature completed");
            }
        }

        info_log(UART_TAG, "[invoke_getV1_url]:Server seen.(YELLOW-led-OFF) & (GREEN-led-ON)");
        gpio_set_value(__YELLOW, __HIGH); //yellow OFF
        gpio_set_value(__GREEN, __LOW);   //green ON
    }
    free(__response_chunk.memory);
}

/***********************************************************************************************************
* NMAE: invoke_saveV1_url
*
* DESCRIPTION:
* First this function find the which network is up or down state.
* After that set PASSWORD[DAT0 DATA FIELD] field with gtime[HBT0 DATA FIELD] and salt[USER DEFINIED VARIABLE] and network 
  mac address[eth0 or eth1] fields,use that fields to perfom checksum.
* After that it will fetch DAT0 data field with sensor predefned parameters.   
*
* PARAMETERS:      Name            RW        Usage
*                __split_strings      R       Read the DAT0 data after splited words based on comma and stored into double array 
*                                          string variable.
* RETURN:
* void
*
***************************************************************************************************************/

void invoke_saveV1_url(char split_strings[][120])
{
    int l = 0, k = 1;
    int dat = 1;
    char savev1_buff1[400] = "", dest[100] = "", src[100] = "", *ngk;
    __cnt = __cnt - 1;

    if ((__eth0_range[0] == 'u') && (__eth1_range[0] == 'u'))

    {
        info_log(UART_TAG, "[invoke_saveV1_url]: Both eth0 & eth1 are UP state");

        ngk = get_mac(__hardware_net_id);
    }

    else if (((__eth0_range[0] == 'u') && (__eth1_range[0] == 'd')) || ((__eth0_range[0] == 'u') && (__eth1_range[0] == '\0')))
    {
        info_log(UART_TAG, "[invoke_saveV1_url]:Only eth0 is UP state");

        ngk = get_mac(__hardware_net_id);
    }
    else if (((__eth0_range[0] == 'd') && (__eth1_range[0] == 'u')) || ((__eth0_range[0] == '\0') && (__eth1_range[0] == 'u')))
    {
        info_log(UART_TAG, "[invoke_saveV1_url]:Only eth1 is UP state");

        ngk = get_mac(__cell_modem_net_id);
    }

    else if(__is_usb_interface == true)
    {
        info_log(UART_TAG, "[invoke_saveV1_url]:Only usb0 up state");
        ngk = get_mac(__usb_net_id);
    }  
    else
    {
        info_log(UART_TAG, "[invoke_getV1_url]:Both eth0 & eth1 & usb0 are in DOWN state");
    }
    strcat(__uc_mac, __gateway_time_stamp); // __gateway_time_stamp nedded for concatenated for password.
    strcat(__uc_mac, __salt);
    info_log(UART_TAG, "[invoke_saveV1_url]:enter 1");
    checksum(__uc_mac);
    info_log(UART_TAG, "[invoke_saveV1_url]:enter 10");

   // strcpy(split_strings[2],__passwd);

    for (l = 0; l < __cnt; l++)
    {
        strcat(dest, __sensor_parms[l]);
        strcat(src, split_strings[k++]);
        strcat(dest, src);

        if (l != __cnt - 1)
        {
            strcat(dest, "&");
        }

        else
        {
            // strcat(dest,"&");
        }

        strcat(savev1_buff1, dest);

        dest[0] = '\0';
        src[0] = '\0';
    }

    strcat(savev1_buff1, "&gatewaytime=");
    strcat(savev1_buff1, __gateway_time_stamp);

    char *server_res_saveV1 = hit_endpoint_url(savev1_buff1, __save_url);
    info_log(UART_TAG, "[invoke_saveV1_url]: Server response from saveV1 side: %s", server_res_saveV1);

    if (__curl_response != CURLE_OK)
    {
        error_log(UART_TAG, "[invoke_saveV1_url]: curl_easy_perform()failed: %s", curl_easy_strerror(__curl_response));
        error_log(UART_TAG, "[invoke_saveV1_url]: Server NOT seen.(GREEN-led-ON) & (YELLOW-led-ON)");
        gpio_set_value(__GREEN, __HIGH); //green OFF
        gpio_set_value(__YELLOW, __LOW); //yellow ON
    }
    else
    {
        info_log(UART_TAG, "[invoke_saveV1_url]: Server seen. (YELLOW-led-OFF) & (GREEN-led-ON)");
        gpio_set_value(__YELLOW, __HIGH); //yellow OFF
        gpio_set_value(__GREEN, __LOW);   //green ON
    }

    free(__response_chunk.memory); //Making sure memory allocated in hit_endpoint_url is freed.
}

/***************************************************************************************************************
*
* NAME: hit_endpoint_url
* DESCRIPTION:
* This function hit the lizard Server.
* PARAMETERS:      Name            RW        Usage
*                  data             R        Read the invoke url data either GETV1 or SAVEV1.
* RETURN:
* character pointer type.
*
*****************************************************************************************************************/

char *hit_endpoint_url(char *data, const char *url)
{

    CURL *curl_handle;
    curl_handle = curl_easy_init();

    char ptr[400] = ""; // don't declare ptr[400] assigning string put '\0'every character not fetching any garbage data.
    char *mac;

    strcat(ptr, url);
    strcat(ptr, data);

    info_log(UART_TAG, "[hit_endpoint_url]: Before hit_endpoint_url,checking url format  %s\n", ptr);

    __response_chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
    __response_chunk.size = 0;           /* no data at this point */

    if (curl_handle)
    {
        curl_easy_setopt(curl_handle, CURLOPT_SHARE, __ssl_session_id);

        info_log(UART_TAG, "[hit_endpoint_url] ssl seesion id used: %p\n", __ssl_session_id);

        curl_easy_setopt(curl_handle, CURLOPT_URL, ptr);

        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);

        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, server_response_callback);

        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&__response_chunk);

        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 60L);

        __curl_response = curl_easy_perform(curl_handle);
    }

    curl_easy_cleanup(curl_handle);
    return __response_chunk.memory;
}
/***************************************************************************************************************
*
* NMAE: get_mac
* DESCRIPTION:
* This function find the MAC address[eth0 or eth1].
* PARAMETERS:      Name        RW        Usage
*                 *ktr         R         Read the network interface name.
* RETURN:
* character pointer type.
* 
******************************************************************************************************************/
char *get_mac(char *ktr)
{
    int fd1;
    struct ifreq ifr;
    char *mac;

    fd1 = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, ktr);

    ioctl(fd1, SIOCGIFHWADDR, &ifr);
    close(fd1);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    sprintf((char *)__uc_mac, "%.02x%.02x%.2x%.2x%.2x%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    info_log(UART_TAG, "[get_mac]: usb0 mac address:%s",__uc_mac);
    return __uc_mac;
}
/****************************************************************************************************************
*
* NMAE: checksum
* DESCRIPTION:
* This function generates the checksum.
* PARAMETERS:      Name        RW        Usage
                   *ptr        R         Read the gtime and salt and mac fetch data.
* RETURN:
* character pointer type.
*
******************************************************************************************************************/
void checksum(char *ptr)
{
    info_log(UART_TAG, "[invoke_saveV1_url]:enter 2");
    int i = 0;
    unsigned char temp[SHA_DIGEST_LENGTH];
    char buf[SHA_DIGEST_LENGTH * 2], ch;
    char passwd[400];

    info_log(UART_TAG, "[invoke_saveV1_url]:enter 3");

    memset(buf, 0x0, SHA_DIGEST_LENGTH * 2);
    memset(temp, 0x0, SHA_DIGEST_LENGTH);
    
    SHA1((unsigned char *)ptr, strlen(ptr),temp);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf((char *)&(buf[i * 2]),"%02x",temp[i]);
    }
    info_log(UART_TAG, "[invoke_saveV1_url]:enter 4");
    //memset(passwd,0x0,strlen(passwd));
     info_log(UART_TAG, "[invoke_saveV1_url]:enter 5");
    //strcpy(passwd,"V001");
     strcpy(__split_strings[2],"V001");
     info_log(UART_TAG, "[invoke_saveV1_url]:enter 6");
   // strcat(passwd,buf);
     info_log(UART_TAG, "[invoke_saveV1_url]:enter 7");
    for (i = 0; i < strlen(buf); i++)
    {
        ch = toupper(buf[i]);
        buf[i] = ch;
         info_log(UART_TAG, "[invoke_saveV1_url]:enter 8");
    }
    info_log(UART_TAG, "[invoke_saveV1_url]:enter 9");
    strcat(__split_strings[2],buf);
    info_log(UART_TAG, "[checksum]:paaaword:%s",passwd);
    //return passwd;
}
/*************************************************************************************************************
*
* NAME: hex_to_dec
* DESCRIPTION:
* This fucnction convert hexa to dec format.
* PARAMETERS:      Name        RW        Usage
*                  *hex         R         Read hexdecimal value.
* RETURN:
* long long integar type.
* 
***************************************************************************************************************/
long long hex_to_dec(const char *hex)
{
    long long place, decimal;
    int i = 0, val, len;
    char data[30], *str;
    str = data;

    decimal = 0;
    place = 1;
    len = strlen(hex);
    len--;

    for (i = 0; hex[i] != '\0'; i++)
    {
        if (hex[i] >= '0' && hex[i] <= '9')
        {
            val = hex[i] - 48;
        }

        else if (hex[i] >= 'a' && hex[i] <= 'f')
        {
            val = hex[i] - 97 + 10;
        }

        else if (hex[i] >= 'A' && hex[i] <= 'F')
        {
            val = hex[i] - 65 + 10;
        }

        decimal += val * pow(16, len);
        len--;
    }

    return decimal;
}

/***************************************************************************************************************
*
* NAME: dec_to_hex
* DESCRIPTION:
* This function convert dec to hex format.
* PARAMETERS:      Name        RW        Usage
                  quotient      R        Read the long long integar value.
* RETURN:
* character pointer type.
*
*****************************************************************************************************************/

char *dec_to_hex(long long quotient)
{
    long long remainder;
    int i, j = 0, k = 0;
    char hexadecimalnum[100];

    while (quotient != 0)
    {
        remainder = quotient % 16;
        if (remainder < 10)
            hexadecimalnum[j++] = 48 + remainder;
        else
            hexadecimalnum[j++] = 87 + remainder;
        quotient = quotient / 16;
    }
    hexadecimalnum[j] = '\0';

    for (i = j; i > 0; i--)
    {
        __hex_value[k++] = hexadecimalnum[i - 1];
    }
    __hex_value[k] = '\0';

    return __hex_value;
}

/***************************************************************************************************************
*
* NMAE: json_parse
* DESCRIPTION: 
* This function find type of the json-c data.
* PARAMETERS:       Name           RW        Usage
*                   *jobj          R         Read the jobj data.
* RETURN:
* integar type.
*     
****************************************************************************************************************/

int json_parse(json_object *jobj)
{
    enum json_type type;
    json_object_object_foreach(jobj, key, val);
    {
        type = json_object_get_type(val);

        switch (type)
        {

        case json_type_null:
            break;

        case json_type_boolean:
            __var_value = json_object_get_boolean(val);
            break;

        case json_type_double:
            break;

        case json_type_int:
            break;

        case json_type_object:
            jobj = json_object_object_get(jobj, key);
            json_parse(jobj);
            break;

        case json_type_string:
            break;
        }
    }
    return __var_value;
}
/***********************************************************************************
*
* NAME: wsn_up
* DESCRIPTION:
* This function reset the WSN
*               
************************************************************************************/

void wsn_up(void)
{
    gpio_set_value(__RESET, __HIGH); //RESET PIN set to high

    info_log(UART_TAG, "[WSN_UP]: Now RESET line is HIGH state to start WSN-UP");
}

/***********************************************************************************
*
* NAME: ping
* DESCRIPTION:
* This function check internet connection by using ping
* RETURN:
* integar type.
*               
************************************************************************************/
/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short ping_checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/*--------------------------------------------------------------------*/
/*--- ping - Create message and send it.                           ---*/
/*    return 0 is ping Ok, return 1 is ping not OK.                ---*/
/*--------------------------------------------------------------------*/
int ping(const char *adress)
{
    const int val = 255;
    int i, sd;
    struct packet pckt;
    struct sockaddr_in r_addr;
    int loop;
    struct hostent *hname;
    struct sockaddr_in addr_ping, *addr;
    __pid = getpid();
    __proto = getprotobyname("icmp");

    if (__pid == 0)
        return 1;

    if (__proto == NULL)
        return 1;

    hname = gethostbyname(adress);
    if (hname == NULL)
        return 1;

    bzero(&addr_ping, sizeof(addr_ping));
    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long *)hname->h_addr;

    addr = &addr_ping;
    char first_interface_status[10];
    sd = socket(PF_INET, SOCK_RAW, __proto->p_proto);
    if (sd < 0)
    {
        error_log(NW_TAG, "[PING]:socket error: %s", strerror(errno));

        return 1;
    }
    if (setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
    {
        error_log(NW_TAG, "[PING]:Set TTL option error: %s", strerror(errno));

        return 1;
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
    {
        error_log(NW_TAG, "[PING]: Request nonblocking I/O error:  %s", strerror(errno));

        return 1;
    }

    for (loop = 0; loop < 5; loop++)
    {

        int len = sizeof(r_addr);

        if (recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len) > 0)
        {
            info_log(NW_TAG, "[PING]: ping Successfull");
            close(sd);
            return 0;
        }

        bzero(&pckt, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = __pid;

        for (i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';
        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = __ping_cnt++;
        pckt.hdr.checksum = ping_checksum(&pckt, sizeof(pckt));

        if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0)
            error_log(NW_TAG, "[PING]: Network unreachable: %s", strerror(errno));

        usleep(300000);
    }
    close(sd);
    return 1;
}

/***********************************************************************************
*
* NAME: health_monitor
* DESCRIPTION:
* This function writes the health data(N/W & UART) status to shared memory
* 
*               
************************************************************************************/

void *health_monitor(void *vargp)
{
    info_log(HEALTH_TAG, "[health_monitor]: Health monitor thread was started");

    // ftok to generate unique key
    key_t key = ftok("shmfile", 65);

    // shmget returns an identifier in shmid
    int shmid = shmget(key, sizeof(struct _health), 0666 | IPC_CREAT);

    // shmat to attach to shared memory
    struct _health *health_check = (struct _health *)shmat(shmid, (void *)0, 0);
    while (1)
    {
        sleep(__health_thread_sleep);
        time(&health_check->curtime);
        health_check->inet_status = __is_nw_avail;
        health_check->uart_status = __is_uart_avail;
        health_check->first_interface_status = __is_first_interface;
        health_check->second_interface_status = __is_second_interface;
        health_check->usb_status=__is_usb_interface;

        info_log(HEALTH_TAG, "  [Data written in memory]: Time: %s inet_stat: %d uart_stat: %d\n", ctime(&health_check->curtime), health_check->inet_status, health_check->uart_status);
        info_log(HEALTH_TAG, "  [Data written in memory]: eth0_if: %d  eth1_if: %d usb0_if: %d\n", health_check->first_interface_status, health_check->second_interface_status,health_check->usb_status);

        __is_first_interface = false;
        __is_second_interface = false;
        __is_usb_interface = false;
    }

    //detach from shared memory
    shmdt(health_check);
}

/***********************************************************************************
*
* NAME: error_log & info_log
* DESCRIPTION:
* These functions (error_log & info_log) writes the logs to syslog
* 
*               
************************************************************************************/

void error_log(char *tag, char *format_str, ...)
{
    if ((__log_level < 2) || (__log_level == 3))
    {
        openlog(tag, LOG_PID | LOG_NDELAY, LOG_USER);

        //va_list is a type to hold information about variable arguments
        va_list args;

        // va_start must be called before accessing variable argument list
        va_start(args, format_str);

        vsyslog(LOG_ERR, format_str, args);

        //va_end should be executed before the function returns whenever va_start has been previously used in that function
        va_end(args);
        closelog();
    }
}

void info_log(char *tag, char *format_str, ...)
{
    if ((__log_level == 2) || (__log_level == 3))
    {
        openlog(tag, LOG_PID | LOG_NDELAY, LOG_USER);
        va_list args;
        va_start(args, format_str);
        vsyslog(LOG_INFO, format_str, args);
        va_end(args);
        closelog();
    }
}
