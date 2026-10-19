package com.whiteeyes.common.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * bcrypt는 비밀번호가 72바이트를 넘으면 예외를 던진다. 한글은 한 글자가 3바이트라 비밀번호 규칙(64자)을
 * 지킨 입력도 72바이트를 넘을 수 있다. 이 인코더는 72바이트를 넘는 입력만 SHA-256 요약(Base64 44자)으로
 * 줄인 뒤 bcrypt에 넘기고, 72바이트 이하 입력은 그대로 넘긴다. 그래서 72바이트 이하의 저장값은 표준
 * bcrypt와 서로 호환된다.
 */
final class LongPasswordSafeEncoder implements PasswordEncoder {

    private static final int BCRYPT_MAX_BYTES = 72;
    private static final String DIGEST_ALGORITHM = "SHA-256";

    private final PasswordEncoder delegate;

    LongPasswordSafeEncoder(PasswordEncoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(shorten(rawPassword));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(shorten(rawPassword), encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return delegate.upgradeEncoding(encodedPassword);
    }

    private static CharSequence shorten(CharSequence rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        byte[] bytes = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= BCRYPT_MAX_BYTES) {
            return rawPassword;
        }
        return Base64.getEncoder().encodeToString(digest(bytes));
    }

    private static byte[] digest(byte[] bytes) {
        try {
            return MessageDigest.getInstance(DIGEST_ALGORITHM).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(DIGEST_ALGORITHM + " 알고리즘을 쓸 수 없습니다.", e);
        }
    }
}
