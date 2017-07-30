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
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import javax.xml.bind.DatatypeConverter;
import java.net.InetAddress;


// using single thread for client operation

public class client {
	
	private Socket s;				// socket object
	public client(String hsend_arrt, int port, String file) {		// client constructor
		try {
			s = new Socket(hsend_arrt, port);
			send_file(file);					// calling send_file function
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}	
	public void send_file(String file) throws IOException {		
		DataOutputStream d_output = new DataOutputStream(s.getOutputStream());		// creating Datastream variable to send stream of data to socket
		FileInputStream fl_input = new FileInputStream(file);
		try {
	 	IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
	    	SecretKeySpec key = new SecretKeySpec("1234567812345678".getBytes(), "AES");	//AES key initialised
	    	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");          // AES key created
	    	cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		Mac h_mac = Mac.getInstance("HmacSHA256", "SunJCE");				
	    	Key h_macKey = new SecretKeySpec(key.getEncoded(), "HmacSHA256");		// hmac key created
		//System.out.println("h_mac key is: " + h_macKey);
		byte[] buffer = new byte[4096];	
		// initiating h_mac
		h_mac.init(h_macKey);					// hmac initialised
		while (fl_input.read(buffer) > 0) {
			// encrypting message
			byte[] encval= cipher.doFinal(buffer);	    
			// calculating Hash of encrypted value
	    		byte[] afmac= h_mac.doFinal(encval);	    		
			byte[] send_arr = new byte[encval.length + 32];
			
  			System.arraycopy(encval, 0, send_arr, 0, encval.length);		// copying encrypted message to array bytes
			System.arraycopy(afmac, 0, send_arr, encval.length, 32);		//copying hmac to array bytes
			d_output.write(send_arr);

  		
		}
		} catch (Exception e) {
    			e.printStackTrace();
		}
		
		fl_input.close();
		d_output.close();
		s.close();	
	}
	
	public static void main(String[] args) {
		int i = Integer.parseInt(args[1]);
		client fc = new client(args[0], i, args[2]);
	}

}



