package com.springKotlinAuthentication.demo.authentication.aop

import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.jwt.entity.Token


object AopUtil {
    fun sanitizeSensitiveData(arg: Any?): Any? {
        return when (arg) {
            is String -> maskValue(arg)
            is Map<*, *> -> arg.mapValues { sanitizeSensitiveData(it.value) }
            is User -> maskUser(arg)
            is Token -> maskAccessToken(arg)
            is ConfirmationToken -> maskConfirmationToken(arg)
            else -> arg
        }
    }

    private fun maskUser(user: User): User {
        return user.copy(
            email = maskValue(user.email),
            password = maskValue(user.password),
            firstName = maskName(user.firstName),
            lastName = maskName(user.lastName)
        )
    }

    private fun maskAccessToken(accessToken: Token): Token {
        return accessToken.copy(
            token = maskTokenValue(accessToken.token)
        )
    }

    private fun maskConfirmationToken(confirmationToken: ConfirmationToken): ConfirmationToken {
        return confirmationToken.copy(
            token = maskTokenValue(confirmationToken.token)
        )
    }


    private fun maskValue(value: String): String {
        return value.replace(Regex("(?<=.{2}).(?=.{2})"), "*")
    }


    private fun maskName(name: String): String {
        return name.first() +
                "*".repeat(name.length - 2) + name.last()
    }

    private fun maskTokenValue(token: String): String {
        return token.replace(Regex("(?<=.{2}).(?=.{2})"), "*")
    }

}