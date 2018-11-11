package edu.memphis.cs.netlab.nacapp;

import net.named_data.jndn.*;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encrypt.*;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.Certificate;
import net.named_data.jndn.util.Blob;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import static net.named_data.jndn.encrypt.Schedule.fromIsoString;

/**
 * Description:
 * <p>
 * Author: lei
 * Date  : 7/11/17.
 */
public class TestConsumerWrapper {
  static ConsumerWrapper.FriendAccess consumerWrapperAccess;

  static class LocalTestFace extends Face implements Producer.OnEncryptedKeys {
    Fixture fixture;
    Name sample_content;
    Name sample_c_key;
    Name read_e_key;
    Name read_d_key;
    List<Data> cKeys;
    List<Data> eKeys;
    List<Data> dKeys;

    LocalTestFace(Fixture fixture) {
      super("localhost");
      this.fixture = fixture;

      sample_content = new Name(fixture.prefix);
      sample_content.append("SAMPLE").append(fixture.datatype);

      sample_c_key = new Name(sample_content);
      sample_c_key.append("C-KEY");

      read_e_key = new Name(fixture.prefix);
      read_e_key.append("READ").append(fixture.datatype).append("E-KEY");

      read_d_key = new Name(fixture.prefix);
      read_d_key.append("READ").append(fixture.datatype).append("D-KEY");
    }

    private void processCKey(final Interest interest, final OnData onData) {
      if (null != cKeys) {
        onData.onData(interest, cKeys.get(0));
        return;
      }

      Producer.OnEncryptedKeys onEncryptedKeys = new Producer.OnEncryptedKeys() {
        @Override
        public void onEncryptedKeys(List list) {
          cKeys = new LinkedList<>();
          for (Object o : list) {
            cKeys.add((Data) o);
          }
          if (cKeys.size() == 0) {
            cKeys = null;
            Global.LOGGER.warning(
                "Producer : Error producing content key: got 0 encrypted keys.");
            return;
          }
          onData.onData(interest, cKeys.get(0));
        }
      };

      try {
        fixture.producer.createContentKey(
            fixture.startTimeSlot, onEncryptedKeys, Producer.defaultOnError);
        //				fixture.producerDb.getContentKey(fixture.startTimeSlot);

      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    @Override
    public void onEncryptedKeys(List list) {
      for (Object ckeyObj : list) {
        if (null == ckeyObj) {
          continue;
        }
        Data cKey = (Data) ckeyObj;
        if (this.cKeys == null) {
          this.cKeys = new LinkedList<>();
        }
        this.cKeys.add(cKey);
      }
    }

    private void processContent(Interest interest, OnData onData) {
      Data d = new Data();
      EncryptError.OnError onError = new EncryptError.OnError() {
        @Override
        public void onError(EncryptError.ErrorCode errorCode, String s) {
          System.err.println("Error producing data: " + s);
        }
      };

      try {
        // create content key
        fixture.producer.createContentKey(fixture.startTimeSlot, this, onError);

        // create content
        fixture.producer.produce(
            d, fixture.startTimeSlot, new Blob(fixture.plainTextData), onError);
        onData.onData(interest, d);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    private void processEKey(Interest interest, OnData onData) {
      try {
        if (eKeys == null || eKeys.size() == 0) {
          List keys = fixture.groupManager.getGroupKey(fixture.startTimeSlot, false);
          eKeys = new LinkedList<>();
          for (Object k : keys) {
            eKeys.add((Data) k);
            break; // only the first key is the ekey
          }

          dKeys = new LinkedList<>();
          for (int i = 1; i < keys.size(); i++) {
            Data key = (Data) keys.get(i);
            Global.LOGGER.info(String.format("new d-key: %s", key.getName().toUri()));
            dKeys.add((Data) keys.get(i));
          }
        }
        if (eKeys.size() == 0) {
          throw new RuntimeException("processEKey()-> 0 e-key generated");
        }
        if (dKeys.size() == 0) {
          throw new RuntimeException("processEKey()-> 0 d-key generated/found");
        }
        onData.onData(interest, eKeys.get(0));
      } catch (Exception error) {
        error.printStackTrace();
      }
    }

    private void processDKey(Interest interest, OnData onData) {
      try {
        if (null == dKeys || dKeys.size() == 0) {
          throw new RuntimeException("processDKey()-> 0 d-key generated");
        }
        onData.onData(interest, dKeys.get(0));
      } catch (Exception error) {
        error.printStackTrace();
      }
    }

    @Override
    public long expressInterest(Interest interest, OnData onData, OnTimeout onTimeout,
                                OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException {
      final Name name = interest.getName();
      Global.LOGGER.info("[LOCAL OUT] " + name.toUri());

      if (sample_c_key.isPrefixOf(name)) {
        processCKey(interest, onData);
      } else if (sample_content.isPrefixOf(name)) {
        processContent(interest, onData);
      } else if (read_e_key.isPrefixOf(name)) {
        processEKey(interest, onData);
      } else if (read_d_key.isPrefixOf(name)) {
        processDKey(interest, onData);
      } else {
        throw new RuntimeException("Unhandled interest: " + interest.getName());
      }
      return 0;
    }
  }

  static class FixtureStatics {
    final Name prefix;
    final Name identity;
    final Name datatype;
    final int keysize = 2048;
    final int freshnessHours = 0;
    final Name consumerName;
    final double startTimeSlot;
    final String scheduleName;
    final RepetitiveInterval interval;
    final Blob plainTextData = new Blob("HELLO");

    public FixtureStatics() {
      try {
        prefix = new Name("/local-home-test");
        identity = new Name("ConsumerWrapperTester");
        datatype = new Name("/test");
        consumerName = new Name("ConsumerTest");
        startTimeSlot = fromIsoString("20150825T090000");
        interval = new RepetitiveInterval(fromIsoString("20150825T000000"),
            fromIsoString("21010825T000000"), 0, 24, 1, RepetitiveInterval.RepeatUnit.DAY);
        scheduleName = "TEST_SCHEDULE";
      } catch (EncodingException e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      }
    }
  }

  static class Fixture extends FixtureStatics implements GroupManager.Friend, Consumer.Friend {
    Face face;
    KeyChain keychain;
    GroupManager.FriendAccess managerAccess;
    Consumer.FriendAccess consumerAccess;
    GroupManager groupManager;
    GroupManagerDb groupManagerDb;
    Consumer consumer;
    ConsumerDb consumerDb;
    Producer producer;
    ProducerDb producerDb;

    public Fixture() {
      super();
      face = new LocalTestFace(this);
      try {
        keychain = KeyChainHelper.makeKeyChain(identity, face);
      } catch (SecurityException e) {
        throw new RuntimeException(e);
      }
      GroupManager.setFriendAccess(this);
      Consumer.setFriendAccess(this);

      try {
        final String groupDBFile = "test-group-manager.db";
        final String producerDBFile = "test-producer.db";
        final String consumerDBFile = "test-consumer.db";
        for (String dbFile : new String[]{groupDBFile, producerDBFile, consumerDBFile}) {
          try {
            File f = new File(dbFile);
            if (f.exists()) {
              boolean suc = f.delete();
              System.out.println(String.format("%s deleted?%s", dbFile, suc));
            }
          } catch (Exception ignored) {
            System.out.println(ignored.getMessage());
          }
        }

        groupManagerDb = new Sqlite3GroupManagerDb(groupDBFile);
        groupManager = new GroupManager(
            prefix, datatype, groupManagerDb, keysize, freshnessHours, keychain);

        consumerDb = new Sqlite3ConsumerDb("test-consumer.db");
        consumer = new Consumer(face, keychain, datatype, consumerName, consumerDb);

        producerDb = new Sqlite3ProducerDb("test-producer.db");
        producer = new Producer(prefix, datatype, face, keychain, producerDb);

        Schedule schedule = new Schedule();
        schedule.addWhiteInterval(interval);
        groupManager.addSchedule(scheduleName, schedule);
      } catch (Exception e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      }
    }

    @Override
    public void setGroupManagerFriendAccess(GroupManager.FriendAccess friendAccess) {
      this.managerAccess = friendAccess;
    }

    @Override
    public void setConsumerFriendAccess(Consumer.FriendAccess friendAccess) {
      this.consumerAccess = friendAccess;
    }
  }

  static Fixture fixture;

  @BeforeClass
  public static void setup() {
    consumerWrapperAccess = new ConsumerWrapper.FriendAccess();
    fixture = new Fixture();
  }

  @Test
  public void testGenerateKeyPair() {
    try {
      final Blob plaintext = new Blob("test");
      ConsumerWrapper.KeyPair pair = consumerWrapperAccess.generateKeyPair();
      EncryptParams encryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
      Blob encryptedBlob =
          RsaAlgorithm.encrypt(pair.publicKey.getKeyBits(), plaintext, encryptParams);
      Blob decrypted =
          RsaAlgorithm.decrypt(pair.privateKey.getKeyBits(), encryptedBlob, encryptParams);
      Assert.assertEquals(plaintext, decrypted);
    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail(e.getMessage());
    }
  }

  @Test
  public void testCertificate() {
    try {
      ConsumerWrapper.KeyPair pair = consumerWrapperAccess.generateKeyPair();
      Name keyName = new Name("/id/test-key");
      Certificate cert = consumerWrapperAccess.makeCert(
          fixture.keychain, keyName, pair.publicKey.getKeyBits());
      Assert.assertArrayEquals(cert.getPublicKeyDer().getImmutableArray(),
          pair.publicKey.getKeyBits().getImmutableArray());
    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail(e.getMessage());
    }
  }

  private static class TestDBSource implements ConsumerDBSource {
    @Override
    public ConsumerDb getDB() {
      try {
        return new Sqlite3ConsumerDb(":memory:");
      } catch (ConsumerDb.Error error) {
        throw new RuntimeException(error);
      }
    }

    @Override
    public boolean deleteDB() {
      // do nothing
      return false;
    }

    @Override
    public boolean isMemoryDB() {
      return true;
    }
  }

  @Test
  public void testLocalIntegrate() {
    try {
      ConsumerWrapper consumerWrapper = ConsumerWrapper.make(fixture.consumerName,
          fixture.prefix, fixture.keychain, fixture.face, new TestDBSource());

      fixture.groupManager.addMember(fixture.scheduleName, consumerWrapper.getCertificate());

      DecryptKey decryptKey = consumerWrapperAccess.getKeyPair(consumerWrapper).privateKey;

      System.out.println(
          String.format("Decryption Key: %s", consumerWrapper.getCertificate().getName()));

      fixture.consumer.addDecryptionKey(
          consumerWrapper.getCertificate().getName(), decryptKey.getKeyBits());

      Name contentName = new Name(fixture.prefix);
      contentName.append("SAMPLE").append(fixture.datatype);

      Consumer.OnConsumeComplete onConsume = new Consumer.OnConsumeComplete() {
        @Override
        public void onConsumeComplete(Data data, Blob blob) {
          System.out.println("Decrypted content is :" + blob.toString());
          Assert.assertArrayEquals(
              blob.getImmutableArray(), fixture.plainTextData.getImmutableArray());
        }
      };
      EncryptError.OnError onError = new EncryptError.OnError() {
        @Override
        public void onError(EncryptError.ErrorCode errorCode, String s) {
          Assert.fail(s);
        }
      };
      fixture.consumer.consume(contentName, onConsume, onError);

    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail(e.getMessage());
    }
  }
}
