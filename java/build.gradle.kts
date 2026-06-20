plugins {
    java
}

group = "com.alleato.dorado"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // Argon2id, scrypt, and PBKDF2 are delegated to Bouncy Castle, matching the
    // other ports' use of a KDF library (Rust crates, Go x/crypto, TS hash-wasm).
    // HMAC-SHA256 and SHA-256 come from the JDK. The cipher and hashes are
    // from-scratch in this project; only the KDFs are a dependency.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile> {
    options.release.set(21)
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
