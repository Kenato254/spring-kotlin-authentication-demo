package com.springKotlinAuthentication.demo.authentication.authorization

enum class Role(val permissions: Set<Permission>) {
    USER(setOf(Permission.READ)),
    ADMIN(setOf(Permission.READ, Permission.WRITE, Permission.DELETE, Permission.UPDATE))
}