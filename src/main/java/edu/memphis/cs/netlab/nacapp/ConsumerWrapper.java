package edu.memphis.cs.netlab.nacapp;


import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.encrypt.*;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Make sure a consumer is 'usable'.
 * Author: lei
 */

public class ConsumerWrapper {

//  private static final Logger logger = Logger.getLogger(ConsumerWrapper.class.getName());

  private static Logger logger = Global.LOGGER;

  protected ConsumerWrapper(Name consumerName,
                            Consumer consumer,
                            Name keyName,
                            IdentityCertificate cert,
                            KeyPair keypair) {
    m_name = consumerName;
    m_consumer = consumer;
    m_keyName = keyName;
    m_keyCert = cert;
    m_keypair = keypair;
  }

  // create a well configured consumer wrapper
  public static ConsumerWrapper make(Name name,
                                     Name accessPrefix,
                                     KeyChain keychain,
                                     Face face,
                                     String dbRelativePath) {

    KeyPair keyPair = generateKeyPair();

    ConsumerWrapper wrapper = prototype(
        name, accessPrefix, keychain, face, dbRelativePath, keyPair);

    // configure consumer
    try {
      // private key is saved by consumer in a database (say SQLite)
      // where is public key saved? the developer need to keep it ???
      wrapper.m_consumer.addDecryptionKey(
          wrapper.m_keyName, keyPair.privateKey.getKeyBits());
    } catch (ConsumerDb.Error error) {
      if (!dbRelativePath.endsWith(":memory:")) {
        logger.log(Level.SEVERE, "Error addDecryptionKey " + error.getMessage());
        logger.log(Level.SEVERE, "Will delete consumer database and try again");
        final String dbPath = dbRelativePath;
        File f = new File(dbPath);
        boolean deleted = f.delete();
        logger.log(Level.SEVERE, "Consumer db deleted? " + String.valueOf(deleted));
        wrapper = prototype(
            name, accessPrefix, keychain, face, dbRelativePath, keyPair);
        try {
          logger.log(Level.INFO, "Add decryption key: " + wrapper.m_keyName.toUri());
          wrapper.m_consumer.addDecryptionKey(
              wrapper.m_keyName, keyPair.privateKey.getKeyBits());
        } catch (ConsumerDb.Error error1) {
          logger.log(Level.SEVERE, "Fatal addDecryptionKey " + error1.getMessage());
        }
      } else {
        logger.log(Level.SEVERE, "Fatal addDecryptionKey " + error.getMessage());
      }
    }

    return wrapper;
  }

//  private static String constructDBPath(String dbRelativePath) {
//    if (dbRelativePath.endsWith(":memory:")) {
//      return dbRelativePath;
//    }
//    final String base = Environment.getExternalStorageDirectory().getPath();
//    if (!dbRelativePath.startsWith("/")) {
//      dbRelativePath = "/" + dbRelativePath;
//    }
//    return base + dbRelativePath;
//  }

  // create intance of consumer, build and return a prototype wrapper
  private static ConsumerWrapper prototype(Name name,
                                           Name accessPrefix,
                                           KeyChain keychain,
                                           Face face,
                                           String dbRelativePath,
                                           KeyPair keyPair) {
//    final String dbPath = constructDBPath(dbRelativePath);
    final String dbPath = dbRelativePath;
//    final ConsumerDb db = new AndroidSqlite3ConsumerDb(dbPath);
    ConsumerDb db = null;
    try {
      db = new Sqlite3ConsumerDb(dbPath);
    } catch (ConsumerDb.Error error) {
      throw new RuntimeException(error);
    }

    Consumer consumer = new Consumer(
        face, keychain, accessPrefix, name, db);

    Name keyName = generateKeyName(
        name, keyPair.publicKey.getKeyBits());

    IdentityCertificate cert = makeCert(
        keychain, keyName, keyPair.publicKey.getKeyBits());

    return new ConsumerWrapper(name, consumer, keyName, cert, keyPair);
  }

  private static class KeyPair {
    public EncryptKey publicKey;
    public DecryptKey privateKey;
  }

  private static KeyPair generateKeyPair() {
    RsaKeyParams params = new RsaKeyParams();
    Blob decryptKeyBlob;
    EncryptKey encryptKey;
    try {
      // private key
      decryptKeyBlob = RsaAlgorithm.generateKey(params).getKeyBits();
      // public key
      encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKeyBlob);
    } catch (NoSuchAlgorithmException | DerDecodingException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
    KeyPair pair = new KeyPair();
    pair.privateKey = new DecryptKey(decryptKeyBlob);
    pair.publicKey = encryptKey;
    return pair;
  }

  private static Name generateKeyName(Name consumerName, Blob encryptKeyBlob) {
    // generate public key name
    Name keyName = new Name(consumerName);
    String publicKeyHex = encryptKeyBlob.toHex();
    String keyId = publicKeyHex.substring(0, 3)
        + publicKeyHex.substring(publicKeyHex.length() - 3);
    keyName.append("DSK-" + keyId);
    return keyName;
  }

  private static IdentityCertificate makeCert(KeyChain keychain,
                                              Name keyName,
                                              Blob ekey) {
    byte[] bytes = new byte[8];
    StringHelper.randomBytes(bytes);
    String rand = StringHelper.toHex(bytes);
    Name certificateName = keyName.getSubName(0, keyName.size() - 1).append
        ("KEY").append(keyName.get(-1)).append("ID-CERT").append(rand);
    IdentityCertificate cert = new IdentityCertificate();
    try {
      PublicKey pk = new PublicKey(ekey);
      cert.setPublicKeyInfo(pk);
      cert.encode();
      keychain.sign(cert);
    } catch (SecurityException e) {
      throw new RuntimeException(e);
    } catch (DerDecodingException | DerEncodingException e) {
      e.printStackTrace();
    }
    cert.setName(certificateName);
    return cert;
  }


  public Consumer getConsumer() {
    return m_consumer;
  }

  public Name getConsumerName() {
    return m_name;
  }

  public Name getConsumerKeyName() {
    return m_keyName;
  }

  public Data getCertificate() {
    return m_keyCert;
  }

  public void setCertificate(IdentityCertificate cert) {
    m_keyCert = cert;
    try {
      logger.log(Level.INFO, "add decryption key for cert: " + cert.getName());
      m_consumer.addDecryptionKey(cert.getName(), m_keypair.privateKey.getKeyBits());
      logger.log(Level.INFO, "add decryption key for cert public key: " + cert.getPublicKeyName());
      m_consumer.addDecryptionKey(cert.getPublicKeyName(), m_keypair.privateKey.getKeyBits());
    } catch (ConsumerDb.Error error) {
      logger.log(Level.SEVERE, "cannot add decrypt key for cert:" + error.getMessage());
    }
  }

  private final Name m_name;
  private final Consumer m_consumer;
  private Name m_keyName;
  private Data m_keyCert;
  private KeyPair m_keypair;
}
