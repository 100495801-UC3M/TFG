/* logger.x - Definición de la interfaz para el servicio de logging RPC */

const MAX_STR_LEN = 256; 

struct log_data {
    string username<MAX_STR_LEN>;
    string operation_details<MAX_STR_LEN>; 
    string timestamp_str<MAX_STR_LEN>;     
};

program LOGGER_PROG {
    version LOGGER_VERS {
        void LOG_OPERATION(log_data) = 1;
    } = 1; 
} = 0x20000001;