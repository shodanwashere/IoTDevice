import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.io.*;
import javax.crypto.*;
import java.security.AlgorithmParameters;

public class InitEncryptor {
  private static final int KEY_ITERATIONS = 10000;
  private static final byte[] KEY_SALT = {
     (byte) 0x1a, (byte) 0x5c, (byte) 0x9a, (byte) 0x12, (byte) 0x74, (byte) 0xfa, (byte) 0x18, (byte) 0x29
  };
  private static final int KEY_LENGTH = 128;
  private static final String KEY_ALGORITHM = "PBEWithHmacSHA256AndAES_128";

  public static void main(String[] args) throws Exception {
    if(args.length != 1){
      System.err.println("Error: password was not specified");
      System.exit(1);
    }
    SecretKeyFactory kf = SecretKeyFactory.getInstance(KEY_ALGORITHM);
    KeySpec ks = new PBEKeySpec(args[0].toCharArray(), KEY_SALT, KEY_ITERATIONS, KEY_LENGTH);
    SecretKey secretKey = kf.generateSecret(ks);
    File parameterFile = new File("encryption.parameters");
    Cipher c = Cipher.getInstance(KEY_ALGORITHM);
    AlgorithmParameters p = AlgorithmParameters.getInstance(KEY_ALGORITHM);
    byte[] encodedParams;
    if(parameterFile.exists()) {
      ObjectInputStream ois = new ObjectInputStream(new FileInputStream(parameterFile));
      encodedParams = (byte[]) ois.readObject();
      p.init(encodedParams);
      c.init(Cipher.ENCRYPT_MODE, secretKey, p);
    } else { c.init(Cipher.ENCRYPT_MODE, secretKey); p.init(c.getParameters().getEncoded()); }

    FileInputStream fis = new FileInputStream("passwd");
    FileOutputStream fos = new FileOutputStream("passwd.cif");
    CipherOutputStream cos = new CipherOutputStream(fos, c);

    byte[] buffer = new byte[16];
    int bytesRead;
    while((bytesRead = fis.read(buffer)) != -1) {
      cos.write(buffer, 0, bytesRead);
    }

//    FileInputStream dfis = new FileInputStream("domains");
//    FileOutputStream dfos = new FileOutputStream("domains.cif");
//    CipherOutputStream dcos = new CipherOutputStream(dfos, c);

//    while((bytesRead = dfis.read(buffer)) != -1) {
//      dcos.write(buffer, 0, bytesRead);
//    }

    if(!parameterFile.exists()){
      ObjectOutputStream pos = new ObjectOutputStream(new FileOutputStream("encryption.parameters"));
      pos.writeObject(c.getParameters().getEncoded()); pos.flush();
      pos.close();
    }

    cos.close();
    fos.close();
    fis.close();

  }
}
