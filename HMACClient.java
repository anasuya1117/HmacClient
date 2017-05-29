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

    private final static String SECRET = "secret";
    private final static String ACCESS = "client-access";
    //access_id: 

    public static void main(String[] args) throws HttpException, IOException, NoSuchAlgorithmException {
        HMACClient client = new HMACClient();
        HttpServletRequest request=null;
        client.makeHTTPCallUsingHMAC(ACCESS);
    }

    public void makeHTTPCallUsingHMAC(String username)
            throws HttpException, NoSuchAlgorithmException {

        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String currentDate = sdf.format(new Date());
        currentDate = currentDate.replaceAll("UTC", "GMT");

        List<NameValuePair> formParams = new ArrayList<NameValuePair>();
        formParams
                .add(new BasicNameValuePair("performance_capture_status", "2"));
        formParams.add(new BasicNameValuePair("message", "someValue"));

        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formParams,
                Consts.UTF_8);

        HttpPatch patch = new HttpPatch(
                "url");

        patch.setHeader("X-EMPLOYEE-ID", "1234");
        patch.setEntity(entity);

        String verb = patch.getMethod();
        System.out.println("verb---" + verb);

        StringBuilder toSign = new StringBuilder();
        toSign.append(verb).append(",").append(entity.getContentType().getValue())
                .append(",").append(",").append(patch.getURI().getPath())
                .append(",").append(currentDate);
        System.out.println("toSign is" + toSign);

        String hmac = calculateHMAC(SECRET, toSign.toString());

        System.out.println("HMAC got is - " + hmac);

        patch.addHeader("Date", currentDate);
        patch.addHeader("Authorization", "APIAuth " + username + ":" + hmac);

        HttpClient httpClient = new DefaultHttpClient();
        HttpResponse response = null;
        try {
            response = httpClient.execute(patch);
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(response.getProtocolVersion());
        System.out.println(response.getStatusLine().getStatusCode());
        System.out.println(response.getStatusLine().getReasonPhrase());
        System.out.println(response.getStatusLine().toString());

        System.out.println(
                "client response:" + response.getStatusLine().getStatusCode());
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
