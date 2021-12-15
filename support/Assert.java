/*
 * Copyright (c) 2021, Red Hat, Inc.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package support;

import static support.Hex.bytesToHex;

public class Assert {

    public static void assertThat(String message, boolean condition) {
        if (!condition) {
            throw new AssertionError("Check failed, message: [" + message + "]");
        }
    }

    public static void assertFalse(String message, boolean condition) {
        assertThat(message, !condition);
    }

    public static void assertEquals(String message, String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Check failed, expected: [" + expected + "]," +
                    " actual: [" + actual + "], message: [" + message + "]");
        }
    }

    public static void assertEquals(String message, byte[] expected, byte[] actual) {
        assertEquals(message, bytesToHex(expected), bytesToHex(actual));
    }

}
