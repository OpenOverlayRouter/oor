################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lisp_mod/lib/patricia/patricia.c \
../lisp_mod/lib/patricia/test.c 

OBJS += \
./lisp_mod/lib/patricia/patricia.o \
./lisp_mod/lib/patricia/test.o 

C_DEPS += \
./lisp_mod/lib/patricia/patricia.d \
./lisp_mod/lib/patricia/test.d 


# Each subdirectory must supply rules for building sources it contributes
lisp_mod/lib/patricia/%.o: ../lisp_mod/lib/patricia/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


