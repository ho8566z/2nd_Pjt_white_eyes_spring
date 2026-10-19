package com.whiteeyes.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

@SpringJUnitConfig(PasswordEncoderConfig.class)
class PasswordEncoderConfigTest {

    private static final String RAW_PASSWORD = "test-password-1!";
    private static final int BCRYPT_LENGTH = 60;
    private static final String BCRYPT_STRENGTH_10_PREFIX = "$2a$10$";
    private static final int BCRYPT_MAX_BYTES = 72;

    private final PasswordEncoder passwordEncoder;

    PasswordEncoderConfigTest(@Autowired PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Test
    @DisplayName("FNC-C-005 같은 비밀번호도 저장값이 매번 다르다")
    void encode_samePassword_differentResult() {
        String first = passwordEncoder.encode(RAW_PASSWORD);
        String second = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("FNC-C-005 저장값에 평문이 없고 강도 10의 60자 bcrypt 문자열이다")
    void encode_result_isBcryptStrength10() {
        String encoded = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(encoded)
                .doesNotContain(RAW_PASSWORD)
                .hasSize(BCRYPT_LENGTH)
                .startsWith(BCRYPT_STRENGTH_10_PREFIX);
    }

    @Test
    @DisplayName("FNC-C-005 matches는 맞는 비밀번호에 true를 돌려준다")
    void matches_rightPassword_true() {
        String encoded = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(passwordEncoder.matches(RAW_PASSWORD, encoded)).isTrue();
    }

    @Test
    @DisplayName("FNC-C-005 matches는 틀린 비밀번호에 false를 돌려준다")
    void matches_wrongPassword_false() {
        String encoded = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(passwordEncoder.matches("wrong-password", encoded)).isFalse();
    }

    @Test
    @DisplayName("FNC-C-005 같은 비밀번호로 만든 서로 다른 저장값이 모두 matches를 통과한다")
    void matches_differentHashesOfSamePassword_allTrue() {
        String first = passwordEncoder.encode(RAW_PASSWORD);
        String second = passwordEncoder.encode(RAW_PASSWORD);

        assertThat(passwordEncoder.matches(RAW_PASSWORD, first)).isTrue();
        assertThat(passwordEncoder.matches(RAW_PASSWORD, second)).isTrue();
    }

    @Test
    @DisplayName("FNC-C-005 한글을 섞은 64자 비밀번호(72바이트 초과)도 오류 없이 저장하고 비교한다")
    void encode_multibytePassword64Chars_noError() {
        String password = "가".repeat(60) + "abc1";

        assertThat(password.getBytes(StandardCharsets.UTF_8).length)
                .isGreaterThan(BCRYPT_MAX_BYTES);
        assertThatCode(() -> passwordEncoder.encode(password)).doesNotThrowAnyException();

        String encoded = passwordEncoder.encode(password);
        assertThat(encoded).hasSize(BCRYPT_LENGTH).startsWith(BCRYPT_STRENGTH_10_PREFIX);
        assertThat(passwordEncoder.matches(password, encoded)).isTrue();
        assertThat(passwordEncoder.matches("가".repeat(60) + "abc2", encoded)).isFalse();
    }

    @Test
    @DisplayName("FNC-C-005 앞 72바이트가 같고 뒤만 다른 긴 비밀번호는 서로 다른 비밀번호로 구분한다")
    void matches_longPasswordsDifferingAfter72Bytes_distinguished() {
        String common = "a".repeat(BCRYPT_MAX_BYTES);
        String encoded = passwordEncoder.encode(common + "X");

        assertThat(passwordEncoder.matches(common + "X", encoded)).isTrue();
        assertThat(passwordEncoder.matches(common + "Y", encoded)).isFalse();
        assertThat(passwordEncoder.matches(common, encoded)).isFalse();
    }

    @Test
    @DisplayName("FNC-C-005 72바이트 이하 비밀번호는 표준 BCryptPasswordEncoder(10)와 서로 호환된다")
    void matches_upTo72Bytes_compatibleWithStandardBcrypt() {
        PasswordEncoder standard = new BCryptPasswordEncoder(10);
        String password = "a".repeat(BCRYPT_MAX_BYTES);

        assertThat(passwordEncoder.matches(password, standard.encode(password))).isTrue();
        assertThat(standard.matches(password, passwordEncoder.encode(password))).isTrue();
    }

    @Test
    @DisplayName("FNC-C-005 저장값 형식이 아닌 문자열과 비교하면 오류 없이 false를 돌려준다")
    void matches_invalidStoredValue_false() {
        assertThat(passwordEncoder.matches(RAW_PASSWORD, "not-a-bcrypt-value")).isFalse();
    }

    @Test
    @DisplayName("FNC-C-005 한글로 정확히 72바이트는 표준 bcrypt와 호환되고 73바이트는 오류 없이 처리한다")
    void encode_multibyteBoundary72And73Bytes() {
        PasswordEncoder standard = new BCryptPasswordEncoder(10);
        String exactly72 = "가".repeat(24);
        String over73 = exactly72 + "a";

        assertThat(exactly72.getBytes(StandardCharsets.UTF_8)).hasSize(BCRYPT_MAX_BYTES);
        assertThat(standard.matches(exactly72, passwordEncoder.encode(exactly72))).isTrue();

        String encoded = passwordEncoder.encode(over73);
        assertThat(passwordEncoder.matches(over73, encoded)).isTrue();
        assertThat(passwordEncoder.matches(exactly72, encoded)).isFalse();
    }

    @Test
    @DisplayName("FNC-C-005 73~80바이트 구간에서도 뒤만 다른 비밀번호를 구분한다")
    void matches_73To80Bytes_distinguished() {
        for (int length = BCRYPT_MAX_BYTES + 1; length <= BCRYPT_MAX_BYTES + 8; length++) {
            String password = "a".repeat(length - 1) + "X";
            String encoded = passwordEncoder.encode(password);

            assertThat(passwordEncoder.matches(password, encoded)).isTrue();
            assertThat(passwordEncoder.matches("a".repeat(length - 1) + "Y", encoded)).isFalse();
        }
    }

    @Test
    @DisplayName("FNC-C-005 빈 비밀번호는 표준 bcrypt와 같은 결과를 낸다")
    void matches_emptyPassword_sameAsStandard() {
        PasswordEncoder standard = new BCryptPasswordEncoder(10);

        assertThat(passwordEncoder.matches("", passwordEncoder.encode("")))
                .isEqualTo(standard.matches("", standard.encode("")));
        assertThat(passwordEncoder.matches("", standard.encode("")))
                .isEqualTo(standard.matches("", standard.encode("")));
    }

    @Test
    @DisplayName("FNC-C-005 null 비밀번호는 표준 bcrypt와 같은 방식으로 처리한다")
    void encodeAndMatches_nullPassword_sameAsStandard() {
        PasswordEncoder standard = new BCryptPasswordEncoder(10);
        String encoded = standard.encode(RAW_PASSWORD);

        assertThat(throwsOf(() -> passwordEncoder.encode(null)))
                .isEqualTo(throwsOf(() -> standard.encode(null)));
        assertThat(throwsOf(() -> passwordEncoder.matches(null, encoded)))
                .isEqualTo(throwsOf(() -> standard.matches(null, encoded)));
    }

    private static Class<? extends Throwable> throwsOf(Runnable action) {
        try {
            action.run();
            return null;
        } catch (RuntimeException e) {
            return e.getClass();
        }
    }
}
