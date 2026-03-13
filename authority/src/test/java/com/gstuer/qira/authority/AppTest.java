package com.gstuer.qira.authority;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AppTest {
    @Test void testConstructor() {
        assertDoesNotThrow(App::new);
    }
}
