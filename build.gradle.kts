plugins {
    kotlin("jvm") version "2.1.0"
}

group = "io.github.pilougit.security.crypto"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    testImplementation(kotlin("test"))
    testImplementation("commons-codec:commons-codec:1.16.0")
    testImplementation("com.google.code.gson:gson:2.11.0")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}
