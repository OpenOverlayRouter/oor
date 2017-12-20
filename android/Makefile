GRADLE := $(shell command -v gradle 2> /dev/null)

clean:
ifndef GRADLE
	rm -rf build libs obj
else
	gradle clean
endif
