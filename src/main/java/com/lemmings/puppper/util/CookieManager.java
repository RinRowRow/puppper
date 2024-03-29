package com.lemmings.puppper.util;

import com.lemmings.puppper.exceptions.NotFoundCookieException;

import javax.servlet.http.Cookie;

public class CookieManager {
    private static final String USER_NAME = "user_name";
    private static final String USER_ID = "user_id";
    private static final String ROLE_NAME = "role";
    private static final String TOKEN = "access_token";

    public static String getUserName(Cookie[] cookies) throws NotFoundCookieException {
        for (Cookie c : cookies) {
            if (c.getName().equals(USER_NAME)) {
                return c.getValue();
            }
        }
        throw new NotFoundCookieException("Параметр " + USER_NAME + "не был найден.");
    }

    public static Long getUserId(Cookie[] cookies) throws NotFoundCookieException {
        for (Cookie c : cookies) {
            if (c.getName().equals(USER_ID)) {
                return Long.parseLong(c.getValue());
            }
        }
        throw new NotFoundCookieException("Параметр " + USER_ID + "не был найден.");
    }

    public static String getRoleName(Cookie[] cookies) throws NotFoundCookieException {
        for (Cookie c : cookies) {
            if (c.getName().equals(ROLE_NAME)) {
                return c.getValue();
            }
        }
        throw new NotFoundCookieException("Параметр " + ROLE_NAME + "не был найден.");
    }

    public static String getToken(Cookie[] cookies) throws NotFoundCookieException {
        for (Cookie c : cookies) {
            if (c.getName().equals(TOKEN)) {
                return c.getValue();
            }
        }
        throw new NotFoundCookieException("Параметр " + TOKEN + "не был найден.");
    }
}
