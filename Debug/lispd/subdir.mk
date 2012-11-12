################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../lispd/cksum.o \
../lispd/cmdline.o \
../lispd/lispd.o \
../lispd/lispd_afi.o \
../lispd/lispd_config.o \
../lispd/lispd_iface_list.o \
../lispd/lispd_iface_mgmt.o \
../lispd/lispd_ipc.o \
../lispd/lispd_lib.o \
../lispd/lispd_local_db.o \
../lispd/lispd_map_cache_db.o \
../lispd/lispd_map_notify.o \
../lispd/lispd_map_register.o \
../lispd/lispd_map_reply.o \
../lispd/lispd_map_request.o \
../lispd/lispd_nonce.o \
../lispd/lispd_pkt_lib.o \
../lispd/lispd_rloc_probing.o \
../lispd/lispd_smr.o \
../lispd/lispd_syslog.o \
../lispd/lispd_timers.o 

C_SRCS += \
../lispd/cksum.c \
../lispd/cmdline.c \
../lispd/lispd.c \
../lispd/lispd_afi.c \
../lispd/lispd_config.c \
../lispd/lispd_iface_list.c \
../lispd/lispd_iface_mgmt.c \
../lispd/lispd_ipc.c \
../lispd/lispd_lib.c \
../lispd/lispd_local_db.c \
../lispd/lispd_map_cache_db.c \
../lispd/lispd_map_notify.c \
../lispd/lispd_map_register.c \
../lispd/lispd_map_reply.c \
../lispd/lispd_map_request.c \
../lispd/lispd_nonce.c \
../lispd/lispd_patricia.c \
../lispd/lispd_pkt_lib.c \
../lispd/lispd_rloc_probing.c \
../lispd/lispd_smr.c \
../lispd/lispd_syslog.c \
../lispd/lispd_timers.c 

OBJS += \
./lispd/cksum.o \
./lispd/cmdline.o \
./lispd/lispd.o \
./lispd/lispd_afi.o \
./lispd/lispd_config.o \
./lispd/lispd_iface_list.o \
./lispd/lispd_iface_mgmt.o \
./lispd/lispd_ipc.o \
./lispd/lispd_lib.o \
./lispd/lispd_local_db.o \
./lispd/lispd_map_cache_db.o \
./lispd/lispd_map_notify.o \
./lispd/lispd_map_register.o \
./lispd/lispd_map_reply.o \
./lispd/lispd_map_request.o \
./lispd/lispd_nonce.o \
./lispd/lispd_patricia.o \
./lispd/lispd_pkt_lib.o \
./lispd/lispd_rloc_probing.o \
./lispd/lispd_smr.o \
./lispd/lispd_syslog.o \
./lispd/lispd_timers.o 

C_DEPS += \
./lispd/cksum.d \
./lispd/cmdline.d \
./lispd/lispd.d \
./lispd/lispd_afi.d \
./lispd/lispd_config.d \
./lispd/lispd_iface_list.d \
./lispd/lispd_iface_mgmt.d \
./lispd/lispd_ipc.d \
./lispd/lispd_lib.d \
./lispd/lispd_local_db.d \
./lispd/lispd_map_cache_db.d \
./lispd/lispd_map_notify.d \
./lispd/lispd_map_register.d \
./lispd/lispd_map_reply.d \
./lispd/lispd_map_request.d \
./lispd/lispd_nonce.d \
./lispd/lispd_patricia.d \
./lispd/lispd_pkt_lib.d \
./lispd/lispd_rloc_probing.d \
./lispd/lispd_smr.d \
./lispd/lispd_syslog.d \
./lispd/lispd_timers.d 


# Each subdirectory must supply rules for building sources it contributes
lispd/%.o: ../lispd/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


