package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken


interface ConfirmationTokenService {
    fun saveConfirmationToken(confirmationToken: ConfirmationToken): ConfirmationToken
    fun getConfirmationByToken(token: String): ConfirmationToken
}