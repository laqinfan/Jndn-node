/*
 * Copyright (C) 2018-2019 Lei Pi, Laqin Fan
 */

package edu.memphis.cs.netlab.nacapp;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.pib.AndroidSqlite3Pib;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;

import java.io.IOException;


/**
 * Helper functions for keychain management
 */
public class KeyChainHelper {

    public static SigningInfo signingInfo1;
    public static String pibPath;

    public static KeyChain keyChain;
    public static AndroidSqlite3Pib pib;


    public static KeyChain makeKeyChain(final Name identity, Face face) throws SecurityException, IOException, PibImpl.Error {

    try {

        PibIdentity pibId = keyChain.createIdentityV2(identity);

        signingInfo1 = new SigningInfo(pibId);

        } catch (KeyChain.Error error) {
        error.printStackTrace();
    } catch (Tpm.Error error) {
        error.printStackTrace();
    } catch (TpmBackEnd.Error error) {
        error.printStackTrace();
    } catch (Pib.Error error) {
        error.printStackTrace();
    }

    keyChain.setFace(face);
    return keyChain;

}

}
