################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lisp_int/lisp_int.c 

OBJS += \
./lisp_int/lisp_int.o 

C_DEPS += \
./lisp_int/lisp_int.d 


# Each subdirectory must supply rules for building sources it contributes
lisp_int/%.o: ../lisp_int/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


