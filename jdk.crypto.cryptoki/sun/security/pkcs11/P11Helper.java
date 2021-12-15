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

package sun.security.pkcs11;

import sun.security.pkcs11.wrapper.PKCS11;

public class P11Helper {

    public static PKCS11 getP11(SunPKCS11 sunp11) {
        return sunp11.p11;
    }

    public static long getOpSession(SunPKCS11 sunp11) throws Exception {
       return sunp11.getToken().getOpSession().id();
    }

    public static long getObjSession(SunPKCS11 sunp11) throws Exception {
        return sunp11.getToken().getObjSession().id();
    }

    public static void releaseSession(SunPKCS11 sunp11, long session) {
        Token token = sunp11.getToken();
        Session sess = new Session(token, session);
        token.releaseSession(sess);
    }
}
