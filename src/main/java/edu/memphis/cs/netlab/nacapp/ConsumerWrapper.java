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
import net.named_data.jndn.security.certificate.Certificate;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Make sure a consumer class is 'usable' out of box.
 * Author: lei
 */

public class ConsumerWrapper {
  //  private static final Logger logger =
  //  Logger.getLogger(ConsumerWrapper.class.getName());

  private static Logger logger = Global.LOGGER;

  protected ConsumerWrapper(Name consumerName, Consumer consumer, Name keyName,
                            Certificate cert, KeyPair keypair) {
    m_name = consumerName;
    m_consumer = consumer;
    m_keyName = keyName;
    m_keyCert = cert;
    m_keypair = keypair;
  }


  // create a well configured consumer wrapper
  public static ConsumerWrapper make(
      Name name, Name accessPrefix, KeyChain keychain, Face face, ConsumerDBSource dbSource) {
    KeyPair keyPair = generateKeyPair();

    ConsumerWrapper wrapper =
        prototype(name, accessPrefix, keychain, face, dbSource, keyPair);

    // configure consumer
    try {
      // TODO: Question for NAC developer
      // private key is saved by consumer in a database (say SQLite)
      // where is public key saved? the developer need to keep it ???
      wrapper.m_consumer.addDecryptionKey(wrapper.m_keyName, keyPair.privateKey.getKeyBits());
    } catch (ConsumerDb.Error error) {
      // !dbRelativePath.endsWith(":memory:")
      if (!dbSource.isMemoryDB()) {
        logger.log(Level.SEVERE, "Error addDecryptionKey " + error.getMessage());
        logger.log(Level.SEVERE, "Will delete consumer database and try again");
        dbSource.deleteDB();
        wrapper = prototype(name, accessPrefix, keychain, face, dbSource, keyPair);
        try {
          logger.log(Level.INFO, "Add decryption key: " + wrapper.m_keyName.toUri());
          wrapper.m_consumer.addDecryptionKey(wrapper.m_keyName,
              keyPair.privateKey.getKeyBits());
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
  private static ConsumerWrapper prototype(Name name, Name accessPrefix, KeyChain keychain,
                                           Face face, ConsumerDBSource dbSource, KeyPair keyPair) {
    ConsumerDb db;
    db = dbSource.getDB();
    Consumer consumer = new Consumer(face, keychain, accessPrefix, name, db);

    Name keyName = generateKeyName(name, keyPair.publicKey.getKeyBits());

    Certificate cert = makeCert(keychain, keyName, keyPair.publicKey.getKeyBits());

    return new ConsumerWrapper(name, consumer, keyName, cert, keyPair);
  }

  public static class KeyPair {
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

    System.out.println(String.format(Locale.ENGLISH,
        "Generated Key Pair\r\n\tPub: %s \r\n\tPriv: %s",
        encryptKey.getKeyBits().toHex(),
        decryptKeyBlob.toHex()));
    return pair;
  }

  private static Name generateKeyName(Name consumerName, Blob encryptKeyBlob) {
    // generate public key name
    Name keyName = new Name(consumerName);
    String publicKeyHex = encryptKeyBlob.toHex();
    String keyId =
        publicKeyHex.substring(0, 3) + publicKeyHex.substring(publicKeyHex.length() - 3);
    keyName.append("KEY");
    keyName.append("DSK-" + keyId);
    return keyName;
  }

  private static Certificate makeCert(KeyChain keychain, Name keyName, Blob publicKeyBlob) {
    byte[] bytes = new byte[8];
    StringHelper.randomBytes(bytes);
    String rand = StringHelper.toHex(bytes);
    Name certificateName = keyName.getSubName(0, keyName.size() - 1)
        .append(keyName.get(-1))
        .append("ID-CERT")
        .append(rand);
    Certificate cert = new Certificate();
    try {
      PublicKey pk = new PublicKey(publicKeyBlob);
      cert.setPublicKeyInfo(pk);
      cert.setNotBefore(0);
      cert.setNotAfter(0);
      cert.encode();
    } catch (SecurityException e) {
      throw new RuntimeException(e);
    } catch (DerDecodingException | DerEncodingException e) {
      e.printStackTrace();
    }
    cert.setName(certificateName);
    logger.log(Level.INFO, String.format(Locale.ENGLISH,
        "created cert [%s]\r\n\tCERT: %s\r\n\tPUB-KEY: %s", certificateName.toUri(),
        cert.getContent().toHex(), cert.getPublicKeyDer().toHex()));
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

  public void setCertificate(Certificate cert) {
    m_keyCert = cert;
    try {
      logger.log(Level.INFO, "add decryption key for cert: " + cert.getName());
      logger.log(Level.INFO, cert.getPublicKeyDer().toHex());
      m_consumer.addDecryptionKey(cert.getName(), m_keypair.privateKey.getKeyBits());
    } catch (ConsumerDb.Error error) {
      logger.log(Level.SEVERE, "cannot add decrypt key for cert:" + error.getMessage());
    }
  }

  public static class FriendAccess {
    public KeyPair generateKeyPair() {
      return ConsumerWrapper.generateKeyPair();
    }

    public KeyPair getKeyPair(ConsumerWrapper c) {
      return c.m_keypair;
    }

    public Certificate makeCert(KeyChain keychain, Name keyName, Blob publicKeyBlob) {
      return ConsumerWrapper.makeCert(keychain, keyName, publicKeyBlob);
    }
  }

  private final Name m_name;
  private final Consumer m_consumer;
  private Name m_keyName;
  private Data m_keyCert;
  private KeyPair m_keypair;
}
