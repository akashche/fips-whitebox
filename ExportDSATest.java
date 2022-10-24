/*
 * Copyright (c) 2022, Red Hat, Inc.
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
import sun.security.provider.DSAPrivateKey;

import java.math.BigInteger;

import static sun.security.pkcs11.P11Helper.getObjSession;
import static sun.security.pkcs11.P11Helper.releaseSession;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;
import static support.Assert.assertEquals;
import static support.JCAInit.initJCA;

/*
 * @test
 * @modules jdk.crypto.cryptoki/sun.security.pkcs11:+open
 *          jdk.crypto.cryptoki/sun.security.pkcs11.wrapper:+open
 *          java.base/sun.security.provider:+open
 * @library support
 * @compile/module=jdk.crypto.cryptoki sun/security/pkcs11/P11Helper.java
 * @run main/othervm -Dcom.redhat.fips=true ExportDSATest
 */
public class ExportDSATest {
    public static void main(String[] args) throws Exception {
        SunPKCS11 sunp11 = initJCA();
        PKCS11 p11 = P11Helper.getP11(sunp11);
        long session = getObjSession(sunp11);


        DSAPrivateKey key = new DSAPrivateKey(
                new BigInteger("57667848829722277702013340385343103308847800267143914350853976811664775153128"),
                new BigInteger("23163157662795034741609300456227499284772929038819966791302834947629257339553456976956256512438096517649092276956475854407769220703030122227808708920707446892300742974946338713788515318774588146999494910153457906449314923803817750997699937248736071989228146474131259710030137287447537812628780439574151221466806717469082825764603260576714555245190499114947911495376663675052661380311946216828558205372472898793062737119683011989431623461839244353393856106207759530282633917304830007399498235964613799959200717412635369592712364474871275650154193761630154577071244896835784669224299801942735027381803487939021694644563"),
                new BigInteger("81644571946692188199028696944074002728408923280755477219737688218098627797027"),
                new BigInteger("4416833375604875793864705337603928130410951555581614725905630576301674851000660997787708915509906386302595106557877783341113882010855129469509518075855911467767292988773660537574723763100878995136607314538413839835675004909744992758685144319126483097990409166724061266964771193330754815741498518509768444568815460687150256091731557424648623399210312196579261957574550736328914253501579493915286886415341506082161876969219308521661875896640032415946292210382512747971123362265076096164096982135173548823180771283285790248964498208287876515577144681223774418121557475521416802258866579671573558855134910539868070213567")
        );

        long keyId = p11.C_CreateObject(session, new CK_ATTRIBUTE[]{
                new CK_ATTRIBUTE(CKA_CLASS, CKO_PRIVATE_KEY),
                new CK_ATTRIBUTE(CKA_KEY_TYPE, CKK_DSA),
                new CK_ATTRIBUTE(CKA_VALUE, key.getX()),
                new CK_ATTRIBUTE(CKA_PRIME, key.getParams().getP()),
                new CK_ATTRIBUTE(CKA_SUBPRIME, key.getParams().getQ()),
                new CK_ATTRIBUTE(CKA_BASE, key.getParams().getG())
        });

        CK_ATTRIBUTE[] exportAttrs = {
                new CK_ATTRIBUTE(CKA_VALUE, new byte[0]),
                new CK_ATTRIBUTE(CKA_PRIME, new byte[0]),
                new CK_ATTRIBUTE(CKA_SUBPRIME, new byte[0]),
                new CK_ATTRIBUTE(CKA_BASE, new byte[0])
        };
        p11.C_GetAttributeValue(session, keyId, exportAttrs);
        assertEquals("Exported value", key.getX(), exportAttrs[0].getBigInteger());
        assertEquals("Exported prime", key.getParams().getP(), exportAttrs[1].getBigInteger());
        assertEquals("Exported subprime", key.getParams().getQ(), exportAttrs[2].getBigInteger());
        assertEquals("Exported base", key.getParams().getG(), exportAttrs[3].getBigInteger());

        releaseSession(sunp11, session);
    }
}
