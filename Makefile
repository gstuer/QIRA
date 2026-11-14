jre := $(shell readlink $(shell which java))
fatjarEnforcer = enforcer/build/libs/enforcer.jar
fatjarAuthority = authority/build/libs/authority.jar
sourcesCore := $(shell find core/src -type f)
sourcesEnforcer := $(shell find enforcer/src -type f)
sourcesAuthority := $(shell find authority/src -type f)

$(fatjarEnforcer): $(sourcesPep) $(sourcesCore)
	gradle build

$(fatjarAuthority): $(sourcesPdp) $(sourcesCore)
	gradle build

build: $(fatjarEnforcer) $(fatjarAuthority)

run: $(fatjarPep)
	java -jar $<

clean:
	gradle clean

capabilities_set:
	sudo setcap cap_net_raw,cap_net_admin=eip $(jre)

capabilities_get:
	sudo getcap $(jre)

capabilities_unset:
	sudo setcap -r $(jre)
