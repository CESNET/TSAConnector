package com.cesnet.pki.tsa;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.tsp.*;

/**
 * TODO: get/generate some valid byte data to verify the stamp() method
 * TODO: verify <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> compliance
 *
 * Status: in development
 *
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {
    private final boolean verbose = false;

    public static void main(String[] args) {
        new TSAConnector().stamp("data.txt");
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
        //SHA1Digest md = new SHA1Digest(); // returns same data as openssl command - good for testing
        SHA256Digest md = new SHA256Digest();

        byte[] dataBytes = input.getBytes();
        int nread = dataBytes.length;
        md.update(dataBytes, 0, nread);
        byte[] result = new byte[32];
        int size = md.doFinal(result, 0);

        return Arrays.copyOfRange(result, 0, size);
    }

    public byte[] readFile(String file) throws NoSuchAlgorithmException, IOException {
        Path path = Paths.get(file);
        String data = String.join(System.lineSeparator(), Files.readAllLines(path));

        return calculateMessageDigest(data);
    }

    public byte[] readFileByte(String file) throws NoSuchAlgorithmException, IOException {
        Path path = Paths.get(file);
        byte[] data = Files.readAllBytes(path);

        return data;
    }

    /**
     * method to send the TSA request and receive an answer
     */
    private void stamp(String filename) {
        //System.setProperty("http.proxyHost", hostname);
        //System.setProperty("http.proxyPort", port);

        String ocspUrl = "http://tsa.cesnet.cz:3161/tsa";
        OutputStream out = null;
        HttpURLConnection con = null;

        try {

            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            //timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3")); // not supported in CESNET
            //byte[] digest = calculateMessageDigest("data");
            byte[] digest = readFile(filename);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, digest);
            //TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
            byte request[] = timeStampRequest.getEncoded();
            ASN1Object o = timeStampRequest.getMessageImprintAlgOID();


            if (verbose) {
                System.out.println("Request byte data:");
                byte[] shouldBe = readFileByte("data.tsq");

                System.out.println("target:");
                for (byte b : shouldBe) {
                    System.out.print((int) b + " ");
                }
                System.out.println();
                System.out.println();

                System.out.println("digest:");
                for (byte b : digest) {
                    System.out.print((int) b + " ");
                }
                System.out.println();
                System.out.println();

                System.out.println("generated:");
                for (byte b : request) {
                    System.out.print((int) b + " ");
                }
                System.out.println();
                System.out.println();

                /*
                byte[] answer = readFileByte("data.tsr");
                System.out.println("answer:");
                for (byte b : answer) {
                    System.out.print((char) b + "");
                }
                System.out.println();
                System.out.println();//*/
            }

            URL url = new URL(ocspUrl);
            con = (HttpURLConnection) url.openConnection();

            con.setDoOutput(true);
            con.setDoInput(true);
            //con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            //con.setRequestProperty("Content-length", String.valueOf(request.length));

            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                System.out.println("Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            InputStream in = con.getInputStream();
            /*
            int i, size = 0;
            char c;
            while((i=in.read())!=-1)
            {
                // converts integer to character
                c=(char)i;

                // prints character
                System.out.print(c);
                size++;
            }

            System.out.println("\nResponse length: "+size);
            if (size > 0)
                return;//*/
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(timeStampRequest);

            System.out.println("Status = ".concat((response.getStatusString() == null) ? "null (seems it means \"OK\")" :
                    response.getStatusString()));


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

                    default: {
                        System.out.println("Unknown (CESNET specific) error occurred!\n" +
                                "Error code ("+response.getFailInfo().intValue()+") not specified in RFC 3161 standard.");
                        return;
                    }
                }
            }

            System.out.print("Timestamp: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime() == null ? "null" :
                    response.getTimeStampToken().getTimeStampInfo().getGenTime());

            System.out.print("TSA: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getTsa() == null ? "null" :
                    response.getTimeStampToken().getTimeStampInfo().getTsa());

            System.out.print("Serial number: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getSerialNumber() == null ? "null" :
                    response.getTimeStampToken().getTimeStampInfo().getSerialNumber());

            System.out.print("Policy: ");
            System.out.println(response.getTimeStampToken().getTimeStampInfo().getPolicy() == null ? "null" :
                    response.getTimeStampToken().getTimeStampInfo().getPolicy());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
