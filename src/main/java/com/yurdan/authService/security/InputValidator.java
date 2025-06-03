package com.yurdan.authService.security;

import java.util.regex.Pattern;

public class InputValidator {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$"
    );

    private static final int MIN_PASSWORD_LENGTH = 4;
    private static final int MAX_PASSWORD_LENGTH = 64;

    public static boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidPassword(String password) {
        return password != null
                && password.length() >= MIN_PASSWORD_LENGTH
                && password.length() <= MAX_PASSWORD_LENGTH;
    }
}

