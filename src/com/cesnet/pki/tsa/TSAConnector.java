package com.cesnet.pki.tsa;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.tsp.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Status: Beta
 *
 * doublecheck <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> compliance
 *
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {

    public static void main(String[] args) {
        final String responseExt = ".tsr";
        String server = "http://tsa.cesnet.cz:3161/tsa";

        GeneralDigest digestAlgorithm = new SHA256Digest();           // todo: can these two be put together?
        ASN1ObjectIdentifier requestAlgorithm = TSPAlgorithms.SHA256; // they are different packages and have nothing in common..

        System.out.println("TSA Connector");
        System.out.print("Specify file to stamp (with extension): ");

        Scanner sc = new Scanner(System.in);
        String filename = sc.nextLine();

        System.out.println();

        TSAConnector connector = new TSAConnector();

        // read file
        byte[] data;
        try {
            data = connector.readFileByte(filename);
        } catch (IOException e) {
            System.out.println("Could not open specified file, terminating.");
            return;
        }

        // create request
        TimeStampRequest tsq = connector.getTSRequest(data, digestAlgorithm, requestAlgorithm);

        // send request and receive response
        TimeStampResponse tsr = connector.getTSResponse(tsq, server);
        if (tsr == null) {
            return;
        }

        System.out.println();

        // show reason of failure
        if (tsr.getFailInfo() != null) {
            connector.printFailReason(tsr.getFailInfo().intValue());
            return;
        }

        // show response
        connector.printResponse(tsr);

        // get name
        System.out.println();
        System.out.print("Save response as: ");
        String saveName = sc.nextLine();
        if (!saveName.endsWith(responseExt)) {
            saveName = saveName.concat(responseExt);
        }

        // save response to file
        try {
            connector.saveToFile(saveName, tsr.getEncoded());
            System.out.println("TimeStamp Response successfully saved as: ".concat(filename));
        } catch (IOException e) {
            System.out.println("Save to file ".concat(saveName).concat(" failed."));
        }
    }

    /**
     * reads byte data of specified file
     *
     * @param filename
     * @return
     * @throws IOException
     */
    private byte[] readFileByte(String filename) throws IOException {
        Path path = Paths.get(filename);

        return Files.readAllBytes(path);
    }

    /**
     * generates TS request (equivalent to .tsq file)
     *
     * The TimeStampReq ASN.1 type has the following definition:
     * <pre>
     *
     *     TimeStampReq ::= SEQUENCE {
     *         version           INTEGER { v1(1) },
     *         messageImprint    MessageImprint
     *           -- a hash algorithm OID and the hash value of the data to be
     *           -- time-stamped.
     *         reqPolicy         TSAPolicyId    OPTIONAL,
     *         nonce             INTEGER        OPTIONAL,
     *         certReq           BOOLEAN        DEFAULT FALSE,
     *         extensions        [0] IMPLICIT Extensions OPTIONAL }
     *
     *     MessageImprint ::= SEQUENCE {
     *         hashAlgorithm     AlgorithmIdentifier,
     *         hashedMessage     OCTET STRING }
     *
     *     TSAPolicyId ::= OBJECT IDENTIFIER
     *
     * </pre>
     *
     * @param data
     * @param digestAlg
     * @param requestAlg
     * @return
     */
    private TimeStampRequest getTSRequest(byte[] data, GeneralDigest digestAlg, ASN1ObjectIdentifier requestAlg) {
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        byte[] digest = calculateMessageDigest(data, digestAlg);

        return tsqGenerator.generate(requestAlg, digest);
    }

    /**
     * generates digest hash using specified algorithm
     *
     * @param message
     * @param messageDigest
     * @return
     */
    private byte[] calculateMessageDigest(byte[] message, GeneralDigest messageDigest) {
        int length = message.length;
        messageDigest.update(message, 0, length);
        byte[] result = new byte[32];
        int size = messageDigest.doFinal(result, 0);

        return Arrays.copyOfRange(result, 0, size);
    }

    /**
     * sends TS Request and receives an answer (equivalent to .tsr file)
     *
     * The TimeStampResp ASN.1 type has the following definition:
     * <pre>
     *
     *     TimeStampResp ::= SEQUENCE {
     *         status            PKIStatusInfo,
     *         timeStampToken    TimeStampToken OPTIONAL ]
     *
     *     PKIStatusInfo ::= SEQUENCE {
     *         status        PKIStatus,
     *         statusString  PKIFreeText OPTIONAL,
     *         failInfo      PKIFailureInfo OPTIONAL }
     *
     *     PKIStatus ::= INTEGER {
     *         granted                (0),
     *           -- when the PKIStatus contains the value zero a TimeStampToken, as
     *           -- requested, is present.
     *         grantedWithMods        (1),
     *           -- when the PKIStatus contains the value one a TimeStampToken,
     *           -- with modifications, is present.
     *         rejection              (2),
     *         waiting                (3),
     *         revocationWarning      (4),
     *           -- this message contains a warning that a revocation is
     *           -- imminent
     *         revocationNotification (5)
     *           -- notification that a revocation has occurred }
     *
     *     PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     *           -- text encoded as UTF-8 String (note:  each UTF8String SHOULD
     *           -- include an RFC 1766 language tag to indicate the language
     *           -- of the contained text)
     *
     *     PKIFailureInfo ::= BIT STRING {
     *         badAlg              (0),
     *           -- unrecognized or unsupported Algorithm Identifier
     *         badRequest          (2),
     *           -- transaction not permitted or supported
     *         badDataFormat       (5),
     *           -- the data submitted has the wrong format
     *         timeNotAvailable    (14),
     *           -- the TSA's time source is not available
     *         unacceptedPolicy    (15),
     *           -- the requested TSA policy is not supported by the TSA
     *         unacceptedExtension (16),
     *           -- the requested extension is not supported by the TSA
     *         addInfoNotAvailable (17)
     *           -- the additional information requested could not be understood
     *           -- or is not available
     *         systemFailure       (25)
     *           -- the request cannot be handled due to system failure }
     *
     *     TimeStampToken ::= ContentInfo
     *         -- contentType is id-signedData
     *         -- content is SignedData
     *         -- eContentType within SignedData is id-ct-TSTInfo
     *         -- eContent within SignedData is TSTInfo
     *
     * </pre>

     * @param tsq
     * @param server
     * @return
     */
    private TimeStampResponse getTSResponse(TimeStampRequest tsq, String server) {
        // open valid connection
        HttpURLConnection con;
        try {
            URL url = new URL(server);
            con = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            System.out.println("The TSA server couldn't be contacted.");
            return null;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestProperty("Content-type", "application/timestamp-query");

        // send request
        OutputStream out;
        try {
            out = con.getOutputStream();
            out.write(tsq.getEncoded()); // byte array
            out.flush();
        } catch (IOException e) {
            System.out.println("Failed to send the TS request.");
            return null;
        }

        // receive response
        InputStream in;
        TimeStampResp resp;
        TimeStampResponse response;
        try {
            // verify connection status
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                System.out.println("Response Code: ".concat(Integer.toString(con.getResponseCode())));
            }
            // accept the answer
            in = con.getInputStream();
            resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            response = new TimeStampResponse(resp);
            // verify the answer
            response.validate(tsq);

            System.out.println("Status = ".concat((response.getStatusString() == null) ? "response accepted" :
                    response.getStatusString()));
        } catch (TSPException | IOException e) {
            System.out.println("Cannot interpret incoming data.");
            return null;
        }

        return response;
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
     * saves byte data to specified file
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
}
