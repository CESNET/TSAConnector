package com.cesnet.pki.tsa;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.tsp.*;

/**
 * TODO: get/generate some valid byte data to verify the stamp() method
 *
 * Status: in development
 *
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {

    public static void main(String[] args) {
        new TSAConnector().stamp();
    }

    /**
     * method for verification of internet connection
     */
    private void ping() {
        String url = "http://www.cesnet.cz";
        boolean available;
        try{
            final URLConnection connection = new URL(url).openConnection();
            connection.connect();
            System.out.println("Service " + url + " available, yeah!");
            available = true;
        } catch(final MalformedURLException e){
            throw new IllegalStateException("Bad URL: " + url, e);
        } catch(final IOException e){
            System.out.println("Service " + url + " unavailable, oh no!");
            e.printStackTrace();
            available = false;
        }
    }

    /**
     * probably only a placeholder for method to generate some valid input string
     *
     * @param input
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public byte[] calculateMessageDigest(String input) throws NoSuchAlgorithmException, IOException {
        SHA1Digest md = new SHA1Digest();

        byte[] dataBytes = input.getBytes();
        int nread = dataBytes.length;
        md.update(dataBytes, 0, nread);
        byte[] result = new byte[32];
        md.doFinal(result, 0);

        return result;
    }

    /**
     * method to send the TSA request and receive an answer
     */
    private void stamp() {
        //System.setProperty("http.proxyHost", hostname);
        //System.setProperty("http.proxyPort", port);

        String ocspUrl = "http://tsa.cesnet.cz:3161/tsa";
        OutputStream out = null;
        HttpURLConnection con = null;

        try {

            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            //timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3"));
            byte[] digest = calculateMessageDigest("helloo");
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, digest);
            //TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();

            URL url = new URL(ocspUrl);
            con = (HttpURLConnection) url.openConnection();

            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));

            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                System.out.println("Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(timeStampRequest);

            System.out.println("Status = ".concat(response.getStatusString()));

            if (response.getFailInfo() != null) {

                switch (response.getFailInfo().intValue()) {
                    case 0: {
                        System.out.println("unrecognized or unsupported Algorithm Identifier");
                        return;
                    }

                    case 2: {
                        System.out.println("transaction not permitted or supported");
                        return;
                    }

                    case 5: {
                        System.out.println("the data submitted has the wrong format");
                        return;
                    }

                    case 14: {
                        System.out.println("the TSA’s time source is not available");
                        return;
                    }

                    case 15: {
                        System.out.println("the requested TSA policy is not supported by the TSA");
                        return;
                    }
                    case 16: {
                        System.out.println("the requested extension is not supported by the TSA");
                        return;
                    }

                    case 17: {
                        System.out.println("the additional information requested could not be understood or is not available");
                        return;
                    }

                    case 25: {
                        System.out.println("the request cannot be handled due to system failure");
                        return;
                    }
                }
            }

            System.out.print("Timestamp: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());

            System.out.print("TSA: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getTsa());

            System.out.print("Serial number: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getSerialNumber());

            System.out.print("Policy: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
