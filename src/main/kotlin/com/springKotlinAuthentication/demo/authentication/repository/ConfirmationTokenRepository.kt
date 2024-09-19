package com.springKotlinAuthentication.demo.authentication.repository

import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface ConfirmationTokenRepository : JpaRepository<ConfirmationToken, Long> {
    fun findByToken(token: String): ConfirmationToken?
}
