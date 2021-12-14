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

import sun.security.pkcs11.TestHelper;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static sun.security.pkcs11.TestHelper.getObjSession;
import static sun.security.pkcs11.TestHelper.releaseSession;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;

/*
 * @test
 * @modules jdk.crypto.cryptoki/sun.security.pkcs11:+open
 *          jdk.crypto.cryptoki/sun.security.pkcs11.wrapper:+open
 * @compile/module=jdk.crypto.cryptoki sun/security/pkcs11/TestHelper.java
 * @run main/othervm -Dcom.redhat.fips=true ImportAESTest
 */
public class ImportAESTest {
    public static void main(String[] args) throws Exception {

        Cipher ciph = Cipher.getInstance("AES");
        ciph.init(ENCRYPT_MODE, new SecretKeySpec(new byte[32], "AES"));
        SunPKCS11 sunp11 = (SunPKCS11) ciph.getProvider();

        PKCS11 p11 = TestHelper.getP11(sunp11);

        CK_ATTRIBUTE[] attrs = {
                new CK_ATTRIBUTE(CKA_CLASS, CKO_SECRET_KEY),
                new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_AES),
                new CK_ATTRIBUTE(CKA_VALUE, new byte[32])
        };

        long session = getObjSession(sunp11);
        long keyId = p11.C_CreateObject(session, attrs);
        System.out.println(keyId);

        releaseSession(sunp11, session);
        System.out.println("success");

    }
}
