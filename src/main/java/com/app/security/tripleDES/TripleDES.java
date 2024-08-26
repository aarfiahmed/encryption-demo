package com.app.security.tripleDES;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author josepholaoye
 */
public class TripleDES {

    String key;

    public TripleDES(String myEncryptionKey) {
        key = myEncryptionKey;
    }

    /**
     * Method To Encrypt The String
     *
     * @param unencryptedString
     * @return encrpted string
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String encrypt(String unencryptedString) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        MessageDigest md = MessageDigest.getInstance("md5");
        byte[] digestOfPassword = md.digest(key.getBytes("utf-8"));
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] plainTextBytes = unencryptedString.getBytes("utf-8");
        byte[] buf = cipher.doFinal(plainTextBytes);
        byte[] base64Bytes = Base64.encodeBase64(buf);
        String base64EncryptedString = new String(base64Bytes);

        return base64EncryptedString;
    }

    /**
     * Method To Decrypt An Ecrypted String
     *
     * @param encryptedString
     * @return
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String decrypt(String encryptedString) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if(encryptedString == null)
        {
            return "";
        }
        byte[] message = Base64.decodeBase64(encryptedString.getBytes("utf-8"));

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digestOfPassword = md.digest(key.getBytes("utf-8"));
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }
        
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");

        Cipher decipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] plainText = decipher.doFinal(message);

        return new String(plainText, "UTF-8");

    }
    
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		TripleDES tripleDES = new TripleDES("qwertyuiopasdfghjklzxcvbnqwQWERTYUIOPLKJHGFDSAertyasdfhhjkkoiuyt");
		String encrypted = tripleDES.encrypt("\r\n" + 
				"  /**\r\n" + 
				"   * The program. The first argument must be -e, -d, or -g to encrypt,\r\n" + 
				"   * decrypt, or generate a key. The second argument is the name of a file\r\n" + 
				"   * from which the key is read or to which it is written for -g. The -e and\r\n" + 
				"   * -d arguments cause the program to read from standard input and encrypt or\r\n" + 
				"   * decrypt to standard output.\r\n" + 
				"   */\r\n" + 
				"  public static void main(String[] args) {\r\n" + 
				"    try {\r\n" + 
				"    	//args[0]=\"-g\";\r\n" + 
				"    	//args[1]=\"my.txt\";\r\n" + 
				"      // Check to see whether there is a provider that can do TripleDES\r\n" + 
				"      // encryption. If not, explicitly install the SunJCE provider.\r\n" + 
				"      try {\r\n" + 
				"        Cipher c = Cipher.getInstance(\"DESede\");\r\n" + 
				"      } catch (Exception e) {\r\n" + 
				"        // An exception here probably means the JCE provider hasn't\r\n" + 
				"        // been permanently installed on this system by listing it\r\n" + 
				"        // in the $JAVA_HOME/jre/lib/security/java.security file.\r\n" + 
				"        // Therefore, we have to install the JCE provider explicitly.\r\n" + 
				"        System.err.println(\"Installing SunJCE provider.\");\r\n" + 
				"       // Provider sunjce = new com.sun.crypto.provider.SunJCE();\r\n" + 
				"        //Security.addProvider(sunjce);\r\n" + 
				"      }\r\n" + 
				"\r\n" + 
				"      // This is where we'll read the key from or write it to\r\n" + 
				"      File keyfile = new File(args[1]);\r\n" + 
				"\r\n" + 
				"      // Now check the first arg to see what we're going to do\r\n" + 
				"      if (args[0].equals(\"-g\")) { // Generate a key\r\n" + 
				"        System.out.print(\"Generating key. This may take some time...\");\r\n" + 
				"        System.out.flush();\r\n" + 
				"        SecretKey key = generateKey();\r\n" + 
				"        writeKey(key, keyfile);\r\n" + 
				"        System.out.println(\"done.\");\r\n" + 
				"        System.out.println(\"Secret key written to \" + args[1]\r\n" + 
				"            + \". Protect that file carefully!\");\r\n" + 
				"      } else if (args[0].equals(\"-e\")) { // Encrypt stdin to stdout\r\n" + 
				"        SecretKey key = readKey(keyfile);\r\n" + 
				"        encrypt(key, System.in, System.out);\r\n" + 
				"      } else if (args[0].equals(\"-d\")) { // Decrypt stdin to stdout\r\n" + 
				"        SecretKey key = readKey(keyfile);\r\n" + 
				"        decrypt(key, System.in, System.out);\r\n" + 
				"      }\r\n" + 
				"    } catch (Exception e) {\r\n" + 
				"      System.err.println(e);\r\n" + 
				"      System.err.println(\"Usage: java \" + TrippleDESByAutomatedGeneratedKeys.class.getName()\r\n" + 
				"          + \" -d|-e|-g <keyfile>\");\r\n" + 
				"    }\r\n" + 
				"  }\r\n" + 
				"\r\n" + 
				"  /** Generate a secret TripleDES encryption/decryption key */\r\n" + 
				"  public static SecretKey generateKey() throws NoSuchAlgorithmException {\r\n" + 
				"    // Get a key generator for Triple DES (a.k.a DESede)\r\n" + 
				"    KeyGenerator keygen = KeyGenerator.getInstance(\"DESede\");\r\n" + 
				"    \r\n" + 
				"    // Use it to generate a key\r\n" + 
				"    return keygen.generateKey();\r\n" + 
				"  }\r\n" + 
				"\r\n" + 
				"  /** Save the specified TripleDES SecretKey to the specified file */\r\n" + 
				"  public static void writeKey(SecretKey key, File f) throws IOException,\r\n" + 
				"      NoSuchAlgorithmException, InvalidKeySpecException {\r\n" + 
				"    // Convert the secret key to an array of bytes like this\r\n" + 
				"    SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(\"DESede\");\r\n" + 
				"    DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(key,\r\n" + 
				"        DESedeKeySpec.class);\r\n" + 
				"    System.out.println(\"keys \"+ keyspec.getKey());\r\n" + 
				"    byte[] rawkey = keyspec.getKey();\r\n" + 
				"\r\n" + 
				"    // Write the raw key to the file\r\n" + 
				"    FileOutputStream out = new FileOutputStream(f);\r\n" + 
				"    out.write(rawkey);\r\n" + 
				"    out.close();\r\n" + 
				"  }\r\n" + 
				"\r\n" + 
				"  /** Read a TripleDES secret key from the specified file */\r\n" + 
				"  public static SecretKey readKey(File f) throws IOException,\r\n" + 
				"      NoSuchAlgorithmException, InvalidKeyException,\r\n" + 
				"      InvalidKeySpecException {\r\n" + 
				"    // Read the raw bytes from the keyfile\r\n" + 
				"    DataInputStream in = new DataInputStream(new FileInputStream(f));\r\n" + 
				"    byte[] rawkey = new byte[(int) f.length()];\r\n" + 
				"    in.readFully(rawkey);\r\n" + 
				"    in.close();\r\n" + 
				"\r\n" + 
				"    // Convert the raw bytes to a secret key like this\r\n" + 
				"    DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);\r\n" + 
				"    SecretKeyFactory keyfactory = SecretKeyFactory.getInstance(\"DESede\");\r\n" + 
				"    SecretKey key = keyfactory.generateSecret(keyspec);\r\n" + 
				"    return key;\r\n" + 
				"  }\r\n" + 
				"\r\n" + 
				"  /**\r\n" + 
				"   * Use the specified TripleDES key to encrypt bytes from the input stream\r\n" + 
				"   * and write them to the output stream. This method uses CipherOutputStream\r\n" + 
				"   * to perform the encryption and write bytes at the same time.\r\n" + 
				"   */\r\n" + 
				"  public static void encrypt(SecretKey key, InputStream in, OutputStream out)\r\n" + 
				"      throws NoSuchAlgorithmException, InvalidKeyException,\r\n" + 
				"      NoSuchPaddingException, IOException {\r\n" + 
				"    // Create and initialize the encryption engine\r\n" + 
				"    Cipher cipher = Cipher.getInstance(\"DESede\");\r\n" + 
				"    cipher.init(Cipher.ENCRYPT_MODE, key);\r\n" + 
				"\r\n" + 
				"    // Create a special output stream to do the work for us\r\n" + 
				"    CipherOutputStream cos = new CipherOutputStream(out, cipher);\r\n" + 
				"\r\n" + 
				"    // Read from the input and write to the encrypting output stream\r\n" + 
				"    byte[] buffer = new byte[2048];\r\n" + 
				"    int bytesRead;\r\n" + 
				"    while ((bytesRead = in.read(buffer)) != -1) {\r\n" + 
				"      cos.write(buffer, 0, bytesRead);\r\n" + 
				"    }\r\n" + 
				"    cos.close();\r\n" + 
				"\r\n" + 
				"    // For extra security, don't leave any plaintext hanging around memory.\r\n" + 
				"    java.util.Arrays.fill(buffer, (byte) 0);\r\n" + 
				"  }\r\n" + 
				"\r\n" + 
				"  /**\r\n" + 
				"   * Use the specified TripleDES key to decrypt bytes ready from the input\r\n" + 
				"   * stream and write them to the output stream. This method uses uses Cipher\r\n" + 
				"   * directly to show how it can be done without CipherInputStream and\r\n" + 
				"   * CipherOutputStream.\r\n" + 
				"   */\r\n" + 
				"  public static void decrypt(SecretKey key, InputStream in, OutputStream out)\r\n" + 
				"      throws NoSuchAlgorithmException, InvalidKeyException, IOException,\r\n" + 
				"      IllegalBlockSizeException, NoSuchPaddingException,\r\n" + 
				"      BadPaddingException {\r\n" + 
				"    // Create and initialize the decryption engine\r\n" + 
				"    Cipher cipher = Cipher.getInstance(\"DESede\");\r\n" + 
				"    cipher.init(Cipher.DECRYPT_MODE, key);\r\n" + 
				"\r\n" + 
				"    // Read bytes, decrypt, and write them out.\r\n" + 
				"    byte[] buffer = new byte[2048];\r\n" + 
				"    int bytesRead;\r\n" + 
				"    while ((bytesRead = in.read(buffer)) != -1) {\r\n" + 
				"      out.write(cipher.update(buffer, 0, bytesRead));\r\n" + 
				"    }\r\n" + 
				"\r\n" + 
				"    // Write out the final bunch of decrypted bytes\r\n" + 
				"    out.write(cipher.doFinal());\r\n" + 
				"    out.flush();\r\n" + 
				"  }\r\n" + 
				"");
		String decrypted = tripleDES.decrypt(encrypted);
		System.out.println("encrypted string "+encrypted);
		System.out.println("decrypted String "+decrypted);
	}

}
