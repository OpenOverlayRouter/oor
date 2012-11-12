################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../lispd/patricia/patricia.o 

C_SRCS += \
../lispd/patricia/patricia.c 

OBJS += \
./lispd/patricia/patricia.o 

C_DEPS += \
./lispd/patricia/patricia.d 


# Each subdirectory must supply rules for building sources it contributes
lispd/patricia/%.o: ../lispd/patricia/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


