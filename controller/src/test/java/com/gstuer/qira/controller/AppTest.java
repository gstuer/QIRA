package com.gstuer.qira.controller;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AppTest {
    @Test void testConstructor() {
        assertDoesNotThrow(App::new);
    }
}
