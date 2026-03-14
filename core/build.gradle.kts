plugins {
    id("buildlogic.java-library-conventions")
}

dependencies {
    implementation("org.pcap4j:pcap4j-core:1.+")
    implementation("org.pcap4j:pcap4j-packetfactory-static:1.+")
    implementation("org.slf4j:slf4j-simple:2+")
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
}
