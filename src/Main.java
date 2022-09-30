import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException
    {
        System.out.println("Block Ciphers: Examined");
        System.out.println("By: Riley Quigley\n");

        while(true)
        {
            Scanner getInput = new Scanner(System.in);
            System.out.print("Choose Block Cipher Method [CBC/CTR/ECB]: "); 
            String userInput = getInput.next();

            
            if(userInput.equalsIgnoreCase("CBC"))
            {
                System.out.println("================================================");
                System.out.println("AES Algorithm using CBC Encryption");
                    
                    //Generate 128 bit key
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(128);
                    SecretKey createdKey = keyGen.generateKey();

                    String plainText = "";

                    //Check For Valid Plaintext Entry (Length must be multiple of 16)
                    while(true)
                    {
                        System.out.println("Input Plaintext (Length Multiple of 16): ");
                        plainText = getInput.next();

                        if(plainText.length() % 16 == 0)
                        {
                            break;
                        }
                        else
                        {
                            System.out.println("Please input plaintext with a length multiple of 16!");
                        }
                    }

                    //Output Plaintext
                    plainTextOutput(plainText, true);

                    //Randomly Fill IV Byte Array
                    SecureRandom genBytesForIV = new SecureRandom();
                    byte[] ivArr = new byte[16];
                    genBytesForIV.nextBytes(ivArr);

                    //Generate IV
                    IvParameterSpec secureIV = new IvParameterSpec(ivArr);

                    //Initialize Cipher to CBC with PKCS5 Padding
                    Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cbc.init(Cipher.ENCRYPT_MODE, createdKey, secureIV);

                    byte[] cipherText = cbc.doFinal(plainText.getBytes("UTF-8"));
    
                    //Output Byte Array (Cipher Text)
                    byteArrOutput(cipherText);
    
                    cbc.init(Cipher.DECRYPT_MODE, createdKey, secureIV);
                    
                    
                    byte[] decryptedText = cbc.doFinal(cipherText);
                    
                    //Output the Plaintext once more, to verify successful encryption and decryption
                    plainTextOutput(new String(decryptedText), false);

            }
            else if(userInput.equalsIgnoreCase("CTR"))
            {
                System.out.println("================================================");
                System.out.println("AES Algorithm using CTR Encryption");

                //Fills Array With Random Bytes Using SecureRandom
                SecureRandom genBytesForKey = new SecureRandom();
                SecureRandom genBytesForIV = new SecureRandom();
                byte[] keyArr = new byte[16];
                byte[] ivArr = new byte[16];
                genBytesForKey.nextBytes(keyArr);
                genBytesForIV.nextBytes(ivArr);

                SecretKeySpec keyGen = new SecretKeySpec(keyArr, "AES");
                IvParameterSpec genIV = new IvParameterSpec(ivArr);

                Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");

                //Set cipher to encryption for CTR
                ctr.init(Cipher.ENCRYPT_MODE, keyGen, genIV);

                String plainText = "";

                    //Check For Valid Plaintext Entry (Length must be multiple of 16)
                    while(true)
                    {
                        System.out.println("Input Plaintext (Length Multiple of 16): ");
                        plainText = getInput.next();

                        if(plainText.length() % 16 == 0)
                        {
                            break;
                        }
                        else
                        {
                            System.out.println("Please input plaintext with a length multiple of 16!");
                        }
                    }

                //Output Initial Plaintext
                plainTextOutput(plainText, true);

                byte[] cipherText = ctr.doFinal(plainText.getBytes("UTF-8"));

                //Output Byte Array
                byteArrOutput(cipherText);

                //Set Cipher To Decrypt
                ctr.init(Cipher.DECRYPT_MODE, keyGen, genIV);

                byte[] decryptedText = ctr.doFinal(cipherText);

                //Output the Decrypted Plaintext once more, to verify successful encryption and decryption
                plainTextOutput(new String(decryptedText), false);
            
            }
            else if(userInput.equalsIgnoreCase("ECB"))
            {
                System.out.println("================================================");

                System.out.println("AES Algorithm using ECB Encryption");

                //Create Cipher
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(128);
                SecretKey createdKey = keyGen.generateKey();

                String plainText = "";

                    //Check For Valid Plaintext Entry (Length must be multiple of 16)
                    while(true)
                    {
                        System.out.println("Input Plaintext (Length Multiple of 16): ");
                        plainText = getInput.next();

                        if(plainText.length() % 16 == 0)
                        {
                            break;
                        }
                        else
                        {
                            System.out.println("Please input plaintext with a length multiple of 16!");
                        }
                    }


                //Output Original Plaintext
                plainTextOutput(plainText, true);
                
                //Initialize the cipher to do ECB mode with PKCS5 padding
                Cipher codeBook = Cipher.getInstance("AES/ECB/PKCS5Padding");
                codeBook.init(Cipher.ENCRYPT_MODE, createdKey);

                byte[] cipherText = codeBook.doFinal(plainText.getBytes("UTF-8"));

                //Output Ciphertext
                byteArrOutput(cipherText);

                codeBook.init(Cipher.DECRYPT_MODE, createdKey);

                byte[] decryptedText = codeBook.doFinal(cipherText);

                //Show Decrypted Ciphertext to Confirm Successful Encryption
                plainTextOutput(new String(decryptedText), false);
            }
            else
            {
                getInput.close();
                break;
            }
        }
    }

    public static void plainTextOutput(String plainText, boolean isEncrypt)
    {
        String plainTxt = "";

        if(isEncrypt == true)
        {
            plainTxt = "Set of plaintext:   ";
        }
        else
        {
            plainTxt = "Decrypted plaintext: ";
        }

        for(int i = 0; i < plainText.length(); i = i+16)
        {
            plainTxt += plainText.substring(i, i+16) + " ";
        }

        System.out.println(plainTxt); 
    }

    public static void byteArrOutput(byte[] cipher)
    {
        System.out.print("Ciphertext (Byte[]): ");

                for(int i = 0; i < cipher.length; i++)
                {
                    System.out.print(cipher[i]);

                    if(i % 16 == 15 && i != cipher.length - 1)
                    {
                        System.out.print("|");
                    }
                }

        System.out.println();
    }
}

