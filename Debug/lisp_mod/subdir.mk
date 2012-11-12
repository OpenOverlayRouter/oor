################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lisp_mod/lisp_input.c \
../lisp_mod/lisp_ipc.c \
../lisp_mod/lisp_mod.c \
../lisp_mod/lisp_output.c \
../lisp_mod/lisp_slab.c \
../lisp_mod/tables.c \
../lisp_mod/timers.c 

OBJS += \
./lisp_mod/lisp_input.o \
./lisp_mod/lisp_ipc.o \
./lisp_mod/lisp_mod.o \
./lisp_mod/lisp_output.o \
./lisp_mod/lisp_slab.o \
./lisp_mod/tables.o \
./lisp_mod/timers.o 

C_DEPS += \
./lisp_mod/lisp_input.d \
./lisp_mod/lisp_ipc.d \
./lisp_mod/lisp_mod.d \
./lisp_mod/lisp_output.d \
./lisp_mod/lisp_slab.d \
./lisp_mod/tables.d \
./lisp_mod/timers.d 


# Each subdirectory must supply rules for building sources it contributes
lisp_mod/%.o: ../lisp_mod/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


