
#include "ipc.h"
#ifdef VPNAPI
#ifdef ANDROID
        #include "../android/jni/json-c/json.h"
        #include "../android/jni/json-c/json_object.h"
#else
        #include <json/json.h>
#endif
#include "../lispd_external.h"
#include "../lispd_input.h"
#include "../lispd_output.h"
#include "../lispd_sockets.h"



inline void print_json_message(json_object *jobj);
int process_ipc_encap_msg(json_object *jobj);
int process_ipc_decap_msg(json_object *jobj);
int process_ipc_control_msg(json_object *jobj);


int process_ipc_packet(int socket)
{
	uint8_t  		*packet				= NULL;
	json_object 	*jobj				= NULL;
	json_object 	*jobj_attr			= NULL;
	int 			type 				= 0;
	int 			result				= GOOD;
	int				len 				= 0;

	if ((packet = (uint8_t *) calloc(1,MAX_IP_PACKET))==NULL){
		lispd_log_msg(LISP_LOG_ERR,"process_ipc_packet: Couldn't allocate space for packet: %s", strerror(errno));
		return (BAD);
	}

	if ((len = read (socket, packet, MAX_IP_PACKET))<0){
		lispd_log_msg(LISP_LOG_DEBUG_2,"process_ipc_packet: Error reading packet from socket: %s",strerror(errno));
		free (packet);
		return (BAD);
	}

	jobj = json_tokener_parse((char*)packet);
	print_json_message(jobj);

	jobj_attr = json_object_object_get(jobj, "type");
	type = json_object_get_int(jobj_attr);


	switch (type){
	case IPC_ENCAP:
		lispd_log_msg(LISP_LOG_DEBUG_3,"process_ipc_packet: Received packet to be encapsulated");
		result = process_ipc_encap_msg(jobj);
		break;
	case IPC_DECAP:
		lispd_log_msg(LISP_LOG_DEBUG_3,"process_ipc_packet: Received packet to be decapsulated");
		result = process_ipc_decap_msg(jobj);
		break;
	case IPC_CTRL_IN:
		lispd_log_msg(LISP_LOG_DEBUG_3,"process_ipc_packet: Received control message");
		result = process_ipc_control_msg(jobj);
		break;
	default:
		lispd_log_msg(LISP_LOG_DEBUG_2,"process_ipc_packet: Unknown IPC message");
		result = BAD;
		break;
	}
	return (result);
}

int process_ipc_encap_msg(json_object *jobj)
{
	uint8_t  		*packet				= NULL;
	int				packet_len			= 0;
	char			*packet_b64			= NULL;
	json_object 	*jobj_attr			= NULL;
	int				result				= GOOD;

	jobj_attr = json_object_object_get(jobj, "packet");
	packet_b64 = (char *)json_object_get_string(jobj_attr);

	packet = (uint8_t *)base64_decode(packet_b64,strlen((char *)packet_b64),&packet_len);

	result = lisp_output(packet,packet_len);
	free(packet);

	return (result);
}

int process_ipc_decap_msg(json_object *jobj)
{
	uint8_t  		*packet				= NULL;
	int				packet_len			= 0;
	char			*packet_b64			= NULL;
	json_object 	*jobj_attr			= NULL;

	jobj_attr = json_object_object_get(jobj, "packet");
	packet_b64 = (char *)json_object_get_string(jobj_attr);
	packet = (uint8_t *)base64_decode(packet_b64,strlen((char *)packet_b64),&packet_len);

	//process_input_packet(packet,packet_len);
	free(packet);

	return (GOOD);
}

int process_ipc_control_msg(json_object *jobj)
{
	uint8_t  		*packet				= NULL;
	int				packet_len			= 0;
	char			*packet_b64			= NULL;
	json_object 	*jobj_attr			= NULL;
	uint16_t		rmt_port			= 0;
	int				result				= GOOD;

	jobj_attr = json_object_object_get(jobj, "remote_port");
	rmt_port = (uint16_t)json_object_get_int(jobj_attr);

	jobj_attr = json_object_object_get(jobj, "packet");
	packet_b64 = (char *)json_object_get_string(jobj_attr);
	packet = (uint8_t *)base64_decode(packet_b64,strlen((char *)packet_b64),&packet_len);

	//result = process_lisp_ctr_msg(packet,packet_len,rmt_port);
	free(packet);

	return (result);
}

int ipc_send_out_packet(
		uint8_t 		*packet,
		int 			packet_length,
		lisp_addr_t 	*dest_addr,
		uint16_t 		src_port,
		uint16_t		dest_port,
		uint8_t			flag)
{
	json_object *jobj 	= NULL;
	const char  *msg	= NULL;
	char 		*pkt 	= NULL;
	int			msg_len	= 0;
	int			result	= 0;
	int 		len 	= 0;
	int			fd		= 0;
	int 		port	= 0;
	int 		type 	= 0;

	if (flag == CONTROL_PKT){
		fd = ipc_control_fd;
		port = IPC_CONTROL_TX_PORT;
		type = IPC_CTRL_OUT;
	}else{
		fd = ipc_data_fd;
		port = IPC_DATA_TX_PORT;
		type = IPC_DATA_OUT;
	}

	jobj = json_object_new_object();

	//Base64Encode(packet, packet_length, &pkt);

	pkt = base64_encode((const unsigned char *)packet,packet_length, &len);

	json_object_object_add(jobj,"type",json_object_new_int(type));
	json_object_object_add(jobj,"dest_addr",json_object_new_string(get_char_from_lisp_addr_t(*dest_addr)));
	json_object_object_add(jobj,"src_port",json_object_new_int(src_port));
	json_object_object_add(jobj,"dest_port",json_object_new_int(dest_port));
	json_object_object_add(jobj,"packet",json_object_new_string_len((const char *)pkt,len));
	free(pkt);

	msg = json_object_to_json_string(jobj);
	msg_len = strlen(msg);
	lispd_log_msg(LISP_LOG_DEBUG_3,"ipc_send_out_packet: %s",msg);

	result = send_packet_ipc (fd,port,(uint8_t *)msg, msg_len);
	json_object_put(jobj);

	return (result);
}

int ipc_send_decap_packet(
		uint8_t 		*packet,
		int 			packet_length)
{
	json_object *jobj 	= NULL;
	const char  *msg	= NULL;
	int			msg_len	= 0;
	int			result	= 0;
	char *pkt = NULL;
	int len = 0;

	jobj = json_object_new_object();

	pkt = base64_encode((const unsigned char *)packet,packet_length, &len);
	json_object_object_add(jobj,"type",json_object_new_int(IPC_DATA_IN));
	json_object_object_add(jobj,"packet",json_object_new_string_len((const char *)pkt,len));

	free(pkt);
	msg = json_object_to_json_string(jobj);
	msg_len = strlen(msg);
	lispd_log_msg(LISP_LOG_DEBUG_3,"ipc_send_decap_packet: %s",msg);
	result = send_packet_ipc (ipc_data_fd,IPC_DATA_TX_PORT,(uint8_t *)msg, msg_len);
	json_object_put(jobj);

	return (result);
}

int ipc_send_log_msg (int     error_code)
{
	json_object *jobj 	= NULL;
	const char  *msg	= NULL;
	int			msg_len	= 0;
	int			result	= 0;

	jobj = json_object_new_object();

	json_object_object_add(jobj,"type",json_object_new_int(IPC_LOG_MSG));
	json_object_object_add(jobj,"err_msg_code",json_object_new_int(error_code));

	msg = json_object_to_json_string(jobj);
	msg_len = strlen(msg);

	lispd_log_msg(LISP_LOG_DEBUG_3,"ipc_send_log_msg: %s",msg);
	result = send_packet_ipc (ipc_control_fd,IPC_CONTROL_TX_PORT,(uint8_t *)msg, msg_len);
	json_object_put(jobj);

	return (result);
}

int ipc_protect_socket (int socket)
{
    json_object *jobj   = NULL;
    const char  *msg    = NULL;
    int         msg_len = 0;
    int         result  = 0;

    jobj = json_object_new_object();

    json_object_object_add(jobj,"type",json_object_new_int(IPC_PROTECT_SOCK));
    json_object_object_add(jobj,"socket",json_object_new_int(socket));

    msg = json_object_to_json_string(jobj);
    msg_len = strlen(msg);

    lispd_log_msg(LISP_LOG_DEBUG_3,"ipc_protect_socket: %s",msg);
    result = send_packet_ipc (ipc_control_fd,IPC_CONTROL_TX_PORT,(uint8_t *)msg, msg_len);
    json_object_put(jobj);

    return (result);
}

inline void print_json_message(json_object *jobj){
	if (debug_level == 3){
		lispd_log_msg(LISP_LOG_DEBUG_3,"print_json_message: %s",json_object_to_json_string(jobj));
	}
}
#endif
