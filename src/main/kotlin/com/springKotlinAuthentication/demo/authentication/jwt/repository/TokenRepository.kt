package com.springKotlinAuthentication.demo.authentication.jwt.repository

import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.jwt.entity.Token
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import java.util.*

interface TokenRepository : JpaRepository<Token, Long> {
    @Query("SELECT t FROM refresh_tokens t WHERE t.user.id = :userId AND t.isRevoked = false ORDER BY t.id")
    fun findAllValidTokensByUser(userId: UUID): List<Token>

    @Query("SELECT t FROM refresh_tokens t WHERE t.user = :user AND t.isRevoked = false")
    fun findFirstByUserAndIsExpiredFalse(user: User): Token?
}