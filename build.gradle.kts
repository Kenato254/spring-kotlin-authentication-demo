plugins {
    kotlin("jvm") version "1.9.25"
    kotlin("plugin.spring") version "1.9.25"
    id("org.springframework.boot") version "3.3.3"
    id("io.spring.dependency-management") version "1.1.6"
    kotlin("plugin.jpa") version "1.9.25"
}

group = "com.springKotlinAuthentication"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring Boot and Kotlin
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.jetbrains.kotlin:kotlin-reflect")

    // https://mvnrepository.com/artifact/com.google.code.gson/gson
    implementation("com.google.code.gson:gson:2.10.1")

    // https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-annotations
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.17.2")


    // Time Based UUID Generator
    implementation("com.fasterxml.uuid:java-uuid-generator:5.0.0")

    // Validator
    implementation("jakarta.validation:jakarta.validation-api:3.1.0-M2")
    implementation("org.apache.bval:bval-jsr:3.0.0")

// https://mvnrepository.com/artifact/com.mysql/mysql-connector-j
    implementation("com.mysql:mysql-connector-j:9.0.0")

    // OpenAPI Doc
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.5.0")

    // https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-aop
    implementation("org.springframework.boot:spring-boot-starter-aop:3.3.3")

    // https://mvnrepository.com/artifact/org.aspectj/aspectjweaver
    runtimeOnly("org.aspectj:aspectjweaver:1.9.22.1")

    // https://mvnrepository.com/artifact/org.slf4j/slf4j-api
    implementation("org.slf4j:slf4j-api:2.0.16")

    // https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api
    // https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-impl
    // https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-jackson
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    // Tests
    testImplementation("com.h2database:h2:2.3.232")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
