#!/bin/bash


PS3='Please enter your choice: '
echo "Select the Open Overlay Router Android application to use:"
options=("No Root" "Root" )
select opt in "${options[@]}"
do
    case $opt in
        "No Root")
            if [ -d src ]
            then
                rm -r src
            fi    
	        cp -r noroot/* .
	        break
            ;;
        "Root")
            if [ -d src ]
            then
                rm -r src
            fi
	        cp -r root/* .
            break
	   ;;
        *) echo invalid option;;
    esac
done
if [ -d obj ]
then
	rm -r obj
fi
if [ -d gen ]
then
        rm -r gen
fi
if [ -d bin ]
then
        rm -r bin
fi

echo "ChecK the content of local.properties and then compile the code using \"ant debug\" or \"ant release\""
