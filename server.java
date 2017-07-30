import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.security.*;
import java.math.*;
import java.util.Base64;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import javax.xml.bind.DatatypeConverter;
import javax.imageio.stream.*;
import java.io.ByteArrayInputStream; 
import java.io.ByteArrayOutputStream; 
import java.net.InetAddress;


public class server extends Thread {   // using thread for multi server operation
	
	private ServerSocket ss;			// socket object
	private String nm;				//file name
	

	public server(int port, String name) {			// server constructor
		try {
			nm = name;
			ss = new ServerSocket(port);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void run() {				// running each thread
		while (true) {
			try {
				Socket clientsocket = ss.accept();			// accepting request from client
				recv_file(clientsocket);					// callin recv_file function
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void recv_file(Socket clientsocket) throws IOException {
		System.out.println("file name opened is " + nm);
		byte[] buffer = new byte[4128];
		int c=0;
		int filesize = 15123; // Send file size in separate msg
		int read = 0;
		int totalr = 0;
		int rem = filesize;
		DataInputStream d_input = new DataInputStream(clientsocket.getInputStream());
		FileOutputStream fl_output = new FileOutputStream(nm);
		ByteArrayOutputStream byte_addr = new ByteArrayOutputStream();
		try {
		    	IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
	    		SecretKeySpec key = new SecretKeySpec("1234567812345678".getBytes(), "AES");	//AES key created (same in server and client)
			Cipher cip = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");			// AES initialisation
	    		cip.init(Cipher.DECRYPT_MODE, key, ivSpec);
			SecretKeySpec hkey = new SecretKeySpec(key.getEncoded(), "HmacSHA256");		// hmac key created (same in server and client)
	    		Mac m = Mac.getInstance("HmacSHA256");				// hmac initated
	    		m.init(hkey);
    						
		
		String s = "";
		while((read = d_input.read(buffer, 0, Math.min(buffer.length, rem))) > 0) {		// reading from socket
				totalr = totalr + read;
				rem =rem - read;
				
				byte_addr.write(buffer,0,read);					// deserialising
				byte[] byte_arr = byte_addr.toByteArray();
				
       				byte[] os = byte_arr;		
    				byte[] encvall = Arrays.copyOfRange(os, 0, os.length - 32);		// removing hmac and encrypted text
   				byte[] hmac = Arrays.copyOfRange(os, os.length - 32, os.length);				
			
				/*Decrypting*/
	    			byte[] plainText = cip.doFinal(encvall);
	    			String st= new String(plainText); 		

		//System.out.println("received to sock  from client after decryption  in bytes :  " + plainText);
				// calculating HMAC from received decrypted message 

    				byte[] chmac = m.doFinal(encvall);

				
				if (MessageDigest.isEqual(hmac, chmac) == true) {			// comparing calculated Hmac with received Hmac 
					System.out.println("HMAC checked:  passed");
					System.out.println("total read is  " + totalr);
					
					fl_output.write(st.getBytes(), 0, st.getBytes().length);  // sending to file if hmac matches

				}
							
				else
				{
					System.out.println("HMAC failed");

				}
				System.out.println("received to sock  from client after decryption :  " + st);
				c++;
				}
				
				c=0;
		
		}catch (Exception e) {
    			e.printStackTrace();
		}
		c=0;

		
		fl_output.close();
		d_input.close();
	}
	
	public static void main(String[] args) {
		int i = Integer.parseInt(args[0]);
		server fs = new server(i, args[1]);
		fs.start();
	}

}

