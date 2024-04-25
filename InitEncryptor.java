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

    Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
    c.init(Cipher.ENCRYPT_MODE, secretKey);

    FileInputStream fis = new FileInputStream("passwd");
    FileOutputStream fos = new FileOutputStream("passwd.cif");
    CipherOutputStream cos = new CipherOutputStream(fos, c);

    byte[] buffer = new byte[16];
    int bytesRead;
    while((bytesRead = fis.read(buffer)) != -1) {
      cos.write(buffer, 0, bytesRead);
    }

    AlgorithmParameters p = AlgorithmParameters.getInstance(KEY_ALGORITHM);
    p.init(c.getParameters().getEncoded());

    ObjectOutputStream pos = new ObjectOutputStream(new FileOutputStream("passwd.parameters"));
    pos.writeObject(c.getParameters().getEncoded()); pos.flush();
    pos.close();
    System.out.println(c.getParameters().getEncoded()); // tee passwd.parameters

    cos.close();
    fos.close();
    fis.close();

  }
}
