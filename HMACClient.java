package batch.com.empowerment.teamleadscorecalc.main;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;

public class HMACClient {

    private final static String DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss z";
    private final static String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private final static String SECRET = "699d82d3-1079-4f60-a809-b14722fc932c";
    private final static String ACCESS = "2735d74e-5444-4ccb-9556-1f640b83ebad";
    //access_id: 

    public static void main(String[] args) throws HttpException, IOException, NoSuchAlgorithmException {
        HMACClient client = new HMACClient();
        HttpServletRequest request=null;
        client.makeHTTPCallUsingHMAC(ACCESS);
    }

    public void makeHTTPCallUsingHMAC(String username) throws HttpException,  NoSuchAlgorithmException {

        String currentDate = new SimpleDateFormat(DATE_FORMAT).format(new Date());

        HttpPatch patch = new HttpPatch("https://peak-api-dev.fresco.me/api/v1/performance_captures/25.json");
        patch.setEntity();
        

        String verb = patch.getMethod();
        System.out.println("verb---"+verb);

        String contentMd5 = calculateMD5(contentEncoding);
        System.out.println("contentMd5----"+contentMd5);

        StringBuilder toSign = new StringBuilder();
    	toSign.append(verb).append(",").append(contentMd5).append(",").append(data.getContentType().getValue()).append(",").append(currentDate).append(",").append(patch.getURI().getPath());
        System.out.println("toSign is"+toSign);
        String hmac = calculateHMAC(SECRET, toSign);

        System.out.println("HMAC got is - "+hmac);
        patch.addHeader("Authorization", new String("AWS ").concat(ACCESS).concat(":").concat(hmac));
        patch.addHeader("Date", currentDate);
        patch.addHeader("Content-Md5", contentMd5);


        HttpClient client = new DefaultHttpClient();
        HttpResponse response = null;
        try 
        {
            response = client.execute(patch);
        } 
        catch (ClientProtocolException e) 
        {
            e.printStackTrace();
        } 
        catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(response.getProtocolVersion());
        System.out.println(response.getStatusLine().getStatusCode());
        System.out.println(response.getStatusLine().getReasonPhrase());
        System.out.println(response.getStatusLine().toString());

        System.out.println("client response:" + response.getStatusLine().getStatusCode());
    }

    private String calculateHMAC(String secret, String data) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), HMAC_SHA1_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal(data.getBytes());
            String result = new String(Base64.encodeBase64(rawHmac));
            return result;
        } 
        catch (GeneralSecurityException e) 
        {
            throw new IllegalArgumentException();
        }
    }

    private String calculateMD5(String contentToEncode) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        digest.update(contentToEncode.getBytes());
        String result = new String(Base64.encodeBase64(digest.digest()));
        return result;
    }
}