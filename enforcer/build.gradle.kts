plugins {
    id("buildlogic.java-application-conventions")
}

application {
    // Define the main class for the application.
    mainClass = "com.gstuer.qira.enforcer.App"
}

dependencies {
    // This dependency is used by the application.
    implementation(project(":core"))
    implementation("org.pcap4j:pcap4j-core:1.+")
    implementation("org.pcap4j:pcap4j-packetfactory-static:1.+")
    implementation("org.slf4j:slf4j-simple:2+")
}

tasks.jar.configure {
    dependsOn(project(":core").tasks.named("jar"))
    manifest {
        attributes(mapOf("Main-Class" to "com.gstuer.qira.enforcer.App"))
    }

    // Exclude signature files from third party jars
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA")
    exclude("META-INF/*.RSA")

    from(configurations.runtimeClasspath.get().map(::zipTree))
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
