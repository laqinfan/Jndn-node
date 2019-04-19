/*
 * Copyright (C) 2018-2019 Lei Pi, Laqin Fan
 */

package edu.memphis.cs.netlab.nacapp;

import android.content.Context;
import android.util.Log;

import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidityPeriod;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.IdentityStorage;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.security.identity.PrivateKeyStorage;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.TrustAnchorContainer;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

import java.io.BufferedWriter;
import java.io.File;
import android.content.Context;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import static android.content.Context.MODE_PRIVATE;

/**
 * Helper functions for keychain management
 */
public class KeyChainHelper {

    public static SigningInfo signingInfo1;

    // Creates a keychain and default identity
    // The identity is created using default key parameters, which is
    //    RSA + 2048
    //
    // referencing
    // https://github.com/zhtaoxiang/AccessManager/blob/master/app/src/main/java/net/named_data/accessmanager/util/Common.java#L83
    public static KeyChain makeKeyChain(final Name identity, Face face) throws SecurityException, IOException, PibImpl.Error {
        final IdentityStorage identityStorage = new MemoryIdentityStorage();
        final PrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();

        return makeKeyChain(identity, face, identityStorage, privateKeyStorage);
    }

    public static KeyChain makeKeyChain(final Name identity, Face face, IdentityStorage idStorage,
                                        PrivateKeyStorage pkStorage) throws SecurityException, IOException, PibImpl.Error {
        KeyChain keyChain = null;
        try {
            keyChain = new KeyChain("pib-memory:", "tpm-memory:");
        } catch (KeyChain.Error error) {
            error.printStackTrace();
        }
        try {
            // If the storage is not MemoryIdentityStorage but a persistant one.
            // this line prevents from re-creating the identity
            if (!idStorage.doesIdentityExist(identity)) {

                CertificateV2 cert;

                PibIdentity pibId = keyChain.createIdentityV2(identity);

                cert = pibId.getDefaultKey().getDefaultCertificate();
                signingInfo1 = new SigningInfo(pibId);
                }

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


    public static final boolean
    saveCertificateToFile(Data data, String filePath)
    {
        HashSet<String> certificateFiles_ = new HashSet<String>();
        certificateFiles_.add(filePath);

        try {
            Blob encoding = data.wireEncode();
            String encodedCertificate = Common.base64Encode
                    (encoding.getImmutableArray(), true);

            BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
            // Use "try/finally instead of "try-with-resources" or "using"
            // which are not supported before Java 7.
            try {
                writer.write(encodedCertificate, 0, encodedCertificate.length());
                writer.flush();
            }
            finally{
                writer.close();
            }

            return true;
        }
        catch (Exception ex) {
            return false;
        }
    }

}
