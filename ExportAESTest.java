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

import sun.security.pkcs11.P11Helper;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;

import static sun.security.pkcs11.P11Helper.getObjSession;
import static sun.security.pkcs11.P11Helper.releaseSession;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import static support.Assert.assertEquals;
import static support.JCAInit.initJCA;

/*
 * @test
 * @modules jdk.crypto.cryptoki/sun.security.pkcs11:+open
 *          jdk.crypto.cryptoki/sun.security.pkcs11.wrapper:+open
 * @library support
 * @compile/module=jdk.crypto.cryptoki sun/security/pkcs11/P11Helper.java
 * @run main/othervm -Dcom.redhat.fips=true ExportAESTest
 */
public class ExportAESTest {
    public static void main(String[] args) throws Exception {

        SunPKCS11 sunp11 = initJCA();
        PKCS11 p11 = P11Helper.getP11(sunp11);
        long session = getObjSession(sunp11);

        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) i;
        }

        long keyId = p11.C_CreateObject(session, new CK_ATTRIBUTE[]{
                new CK_ATTRIBUTE(CKA_CLASS, CKO_SECRET_KEY),
                new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_AES),
                new CK_ATTRIBUTE(CKA_VALUE, keyBytes)
        });

        CK_ATTRIBUTE[] exportAttrs = {
                new CK_ATTRIBUTE(CKA_VALUE, new byte[32])
        };
        p11.C_GetAttributeValue(session, keyId, exportAttrs);
        byte[] exported = (byte[]) exportAttrs[0].pValue;
        assertEquals("Key export", keyBytes, exported);

        releaseSession(sunp11, session);
    }
}
