package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.repository.ConfirmationTokenRepository
import jakarta.persistence.EntityNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class ConfirmationTokenServiceImpl(
    private val confirmationTokenRepository: ConfirmationTokenRepository
) : ConfirmationTokenService {

    @Transactional
    override fun saveConfirmationToken(confirmationToken: ConfirmationToken): ConfirmationToken {
        return confirmationTokenRepository.save(confirmationToken)
    }

    @Transactional
    override fun getConfirmationByToken(token: String): ConfirmationToken {
        return confirmationTokenRepository.findByToken(token)
            ?: throw EntityNotFoundException(Constant.CONFIRMATION_TOKEN_NOT_FOUND)
    }
}