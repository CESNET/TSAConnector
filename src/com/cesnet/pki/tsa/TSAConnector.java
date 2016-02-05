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
import java.util.Scanner;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.tsp.*;

/**
 * TODO: verify output
 * TODO: doublecheck <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> compliance
 *
 * Status: in development
 *
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {
    private final boolean verbose = false;
    private String[] hosts;

    public static void main(String[] args) {
        String[] hosts = new String[2];
        hosts[0] = "http://tsa.cesnet.cz:3161/tsa";
        hosts[1] = "http://tsa2.cesnet.cz:3161/tsa";

        System.out.println("TSA Connector");
        System.out.println("Note that only .txt files without punctuation are supported at the moment.");
        System.out.println();
        System.out.print("Please type name of your file with extension: ");

        Scanner sc = new Scanner(System.in);
        String file = sc.nextLine();

        System.out.println();

        TSAConnector tsa = new TSAConnector(hosts);
        tsa.stamp(file);
        //System.out.println(tsa.compareByte(tsa.readFileByte("data.tsr"), tsa.readFileByte("data2.tsr")));
    }

    /**
     * constructor
     *
     * @param url array or TSA's addresses
     */
    public TSAConnector(String[] url) {
        this.hosts = url;
    }

    /**
     * method for verification of internet connection
     * for debug purposes
     *
     * @return
     */
    private boolean ping() {
        String url = "http://www.google.com";
        boolean available;
        try{
            final URLConnection connection = new URL(url).openConnection();
            connection.connect();
            System.out.println("Internet connection working.");
            available = true;
        } catch(final MalformedURLException e){
            throw new IllegalStateException("Bad URL: " + url, e);
        } catch(final IOException e){
            System.out.println("Failed to connect to internet.");
            e.printStackTrace();
            available = false;
        }

        return available;
    }

    /**
     * generates digest hash using SHA256 algorithm
     *
     * @param input
     * @return
     */
    private byte[] calculateMessageDigest(String input) {
        //SHA1Digest md = new SHA1Digest(); // returns same data as openssl command - good for testing
        SHA256Digest md = new SHA256Digest();

        byte[] dataBytes = input.getBytes();
        int nread = dataBytes.length;
        md.update(dataBytes, 0, nread);
        byte[] result = new byte[32];
        int size = md.doFinal(result, 0);

        return Arrays.copyOfRange(result, 0, size);
    }

    /**
     * reads contents of text file
     *
     * @param file
     * @return
     * @throws IOException
     */
    private byte[] readFile(String file) throws IOException {
        Path path = Paths.get(file);
        String data = String.join(System.lineSeparator(), Files.readAllLines(path));

        return calculateMessageDigest(data);
    }

    /**
     * reads byte data of file
     *
     * @param file
     * @return
     * @throws IOException
     */
    private byte[] readFileByte(String file) throws IOException {
        Path path = Paths.get(file);
        byte[] data = Files.readAllBytes(path);

        return data;
    }

    /**
     * compares two byte arrays
     * for debug purposes
     *
     * @param data1
     * @param data2
     * @return
     */
    private boolean compareByte(byte[] data1, byte[] data2) {
        if (data1.length != data2.length) {
            // different size
            System.out.println("Different size!");
            return false;
        }

        System.out.println("Different bytes at:");
        for (int i = 0; i < data1.length; i++) {
            if (data1[i] != data2[i]) {
                // different byte
                System.out.print(i + " ");
            }
        }
        System.out.println();

        return true;
    }

    /**
     * generates TS request (equivalent to .tsq file)
     *
     * @param filename
     * @return
     * @throws IOException
     */
    private TimeStampRequest getTimeStampRequest(String filename) throws IOException {
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        //timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3")); // not supported in CESNET
        //byte[] digest = calculateMessageDigest("data");
        byte[] digest = readFile(filename);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, digest);
        //TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        // for debugging
        if (verbose) {
            byte[] request = timeStampRequest.getEncoded();
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

        return timeStampRequest;
    }

    /**
     * tries to establish connection with some server from @hosts
     *
     * @return
     * @throws IOException
     */
    private HttpURLConnection openConnection() throws IOException {
        URL url;
        HttpURLConnection con = null;
        boolean success = false;
        IOException e = null;

        for (String host : hosts) {
            try {
                url = new URL(host);
                con = (HttpURLConnection) url.openConnection();
                success = true;
                break;
            } catch (IOException e1) {
                e = e1;
            }
        }

        if (!success) {
            throw e;
        }

        return con;
    }

    /**
     * receives response
     *
     * @param con
     * @return
     * @throws IOException
     */
    private TimeStampResp getResponse(HttpURLConnection con) throws IOException {
        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
        } else {
            System.out.println("Response Code: ".concat(Integer.toString(con.getResponseCode())));
        }
        InputStream in = con.getInputStream();
            /* // snippet for verification of received data
            int i, size = 0;
            char c;
            byte[] data1 = new byte[776];
            while((i=in.read())!=-1)
            {
                // converts integer to character
                //c=(char)i;

                // prints character
                //System.out.print(c);
                data1[size] = (byte) i;
                size++;
            }

            Path path2 = Paths.get("data.tsr");
            byte[] data2 = Files.readAllBytes(path2);

            for (int j = 0; j < data1.length; j++) {
                if (data1[j] != data2[j]) {
                    // different byte
                    System.out.print(j + " ");
                }
            }

            System.out.println("\nResponse length: "+size);

            if (size > 0)
                return;//*/

        return TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
    }

    /**
     * prints reason of failure according to RFC 3161 standard
     *
     * @param reason
     */
    private void printFailReason(int reason) {
        switch (reason) {
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
                System.out.println("the TSA's time source is not available");
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
                        "Error code ("+reason+") not specified in RFC 3161 standard.");
            }
        }
    }

    /**
     * prints response of TSA
     *
     * @param tsr
     */
    private void printResponse(TimeStampResponse tsr) {
        System.out.print("Timestamp: ");
        System.out.println(tsr.getTimeStampToken().getTimeStampInfo().getGenTime() == null ? "null" :
                tsr.getTimeStampToken().getTimeStampInfo().getGenTime());

        System.out.print("TSA: ");
        System.out.println(tsr.getTimeStampToken().getTimeStampInfo().getTsa() == null ? "null" :
                tsr.getTimeStampToken().getTimeStampInfo().getTsa());

        System.out.print("Serial number: ");
        System.out.println(tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber() == null ? "null" :
                tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber());

        System.out.print("Policy: ");
        System.out.println(tsr.getTimeStampToken().getTimeStampInfo().getPolicy() == null ? "null" :
                tsr.getTimeStampToken().getTimeStampInfo().getPolicy());
    }

    /**
     * saves data to file
     *
     * @param filename
     * @param data
     * @throws IOException
     */
    private void saveToFile(String filename, byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }

    /**
     * sends the TSA request, receives an answer and interprets it
     *
     * @param filename name of the file with extension
     */
    private void stamp(String filename) {
        //System.setProperty("http.proxyHost", hostname);
        //System.setProperty("http.proxyPort", port);

        // create request
        TimeStampRequest tsq;
        byte[] request;
        try {
            tsq = getTimeStampRequest(filename);
            request = tsq.getEncoded();
        } catch (IOException e) {
            System.out.println("Failed to create the TS Request.");
            e.printStackTrace();
            return;
        }

        // open valid connection
        HttpURLConnection con;
        try {
            con = openConnection();
        } catch (IOException e) {
            System.out.println("No TSA server could be contacted.");
            e.printStackTrace();
            return;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        //con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/timestamp-query");
        //con.setRequestProperty("Content-length", String.valueOf(request.length));

        // send request
        OutputStream out;
        try {
            out = con.getOutputStream();
            out.write(request);
            out.flush();
        } catch (IOException e) {
            System.out.println("Failed to send the TS request.");
            e.printStackTrace();
            return;
        }

        // receive response
        TimeStampResp resp;
        TimeStampResponse response;
        try {
            resp = getResponse(con);
            response = new TimeStampResponse(resp);
            response.validate(tsq);
            System.out.println("Status = ".concat((response.getStatusString() == null) ? "null (seems it means \"OK\")" :
                    response.getStatusString()));
        } catch (TSPException | IOException e) {
            System.out.println("Cannot interpret incoming data.");
            e.printStackTrace();
            return;
        }

        // show reason of failure
        if (response.getFailInfo() != null) {
            printFailReason(response.getFailInfo().intValue());
            return;
        }

        // show response
        printResponse(response);

        // save response to file
        String saveName = filename.substring(0, filename.lastIndexOf(".")).concat(".tsr");
        try {
            saveToFile(saveName, resp.getEncoded());
            System.out.println();
            System.out.println("TimeStamp Response successfully saved as: ".concat(saveName));
        } catch (IOException e) {
            System.out.println("Save to file ".concat(filename).concat(" failed."));
            e.printStackTrace();
        }
    }
}
