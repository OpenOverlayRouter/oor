################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/tcp_echo_client.c \
../tests/tcp_echo_server.c \
../tests/udp_echo_client.c \
../tests/udp_echo_server.c 

OBJS += \
./tests/tcp_echo_client.o \
./tests/tcp_echo_server.o \
./tests/udp_echo_client.o \
./tests/udp_echo_server.o 

C_DEPS += \
./tests/tcp_echo_client.d \
./tests/tcp_echo_server.d \
./tests/udp_echo_client.d \
./tests/udp_echo_server.d 


# Each subdirectory must supply rules for building sources it contributes
tests/%.o: ../tests/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


