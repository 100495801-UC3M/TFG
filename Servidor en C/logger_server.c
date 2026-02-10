/* logger_server.c - Implementación de los procedimientos del servidor RPC de logging */
#include "logger.h" 
#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 

void * log_operation_1_svc(log_data *argp, struct svc_req *rqstp)
{
    static char result_placeholder;

    char date_part[20];
    char time_part[20];  

    char username_copy[MAX_STR_LEN + 1];
    char operation_details_copy[MAX_STR_LEN + 1];
    char timestamp_str_copy[MAX_STR_LEN + 1];

    // Prevenir unused parameter warning
    (void)rqstp;

    if (argp->username) {
        strncpy(username_copy, argp->username, MAX_STR_LEN);
        username_copy[MAX_STR_LEN] = '\0';
    } else {
        strcpy(username_copy, "N/A_USER");
    }

    if (argp->operation_details) {
        strncpy(operation_details_copy, argp->operation_details, MAX_STR_LEN);
        operation_details_copy[MAX_STR_LEN] = '\0';
    } else {
        strcpy(operation_details_copy, "N/A_OP");
    }
    
    if (argp->timestamp_str) {
        strncpy(timestamp_str_copy, argp->timestamp_str, MAX_STR_LEN);
        timestamp_str_copy[MAX_STR_LEN] = '\0';
    } else {
        strcpy(timestamp_str_copy, "N/A_TS N/A_TS");
    }

    if (sscanf(timestamp_str_copy, "%10s %8s", date_part, time_part) == 2) {
        date_part[10] = '\0'; 
        time_part[8] = '\0';  
    } else {
        strncpy(date_part, timestamp_str_copy, sizeof(date_part) -1);
        date_part[sizeof(date_part)-1] = '\0';
        strcpy(time_part, "(hora_inv)");
    }
    
    printf("%s\n", username_copy);
    printf("%s\n", operation_details_copy);
    printf("%s\n", date_part);
    printf("%s\n", time_part);
    printf("----------------------------------------\n"); 
    fflush(stdout); 

    return (void *) &result_placeholder; 
}