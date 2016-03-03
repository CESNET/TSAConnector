package com.cesnet.pki.tsa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.ExtendedDigest;
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
 * <p>
 * doublecheck <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> compliance
 * <p>
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {
    private static final Logger logger = LogManager.getLogger();

    public static void main(String[] args) {
        logger.entry();
        final String server = "http://tsa.cesnet.cz:3161/tsa";

        /*=== Temporary UI start ===*/
        System.out.print("\nSpecify file to stamp (with extension): ");

        Scanner sc = new Scanner(System.in);
        String filename = sc.nextLine();

        System.out.println();
        /*=== Temporary UI end ===*/

        TSAConnector connector = new TSAConnector();

        ExtendedDigest digestAlgorithm = new SHA256Digest(); // select hash algorithm
        ASN1ObjectIdentifier requestAlgorithm;
        try {
            requestAlgorithm = connector.getHashObjectIdentifier(digestAlgorithm.getAlgorithmName());
        } catch (IllegalArgumentException e) {
            logger.catching(e);
            return;
        }
        logger.info("Selected algorithm: {}", digestAlgorithm.getAlgorithmName());

        // read file
        byte[] data;
        try {
            data = connector.readFileByte(filename);
        } catch (IOException e) {
            logger.error("Cannot open file '{}', terminating.", filename);
            logger.catching(e);
            return;
        }
        logger.debug("file '{}' was read", filename);

        // create request
        byte[] digest = connector.calculateMessageDigest(data, digestAlgorithm);
        TimeStampRequest tsq = connector.getTSRequest(digest, requestAlgorithm);
        logger.debug("TS request generated");

        // send request and receive response
        TimeStampResponse tsr;
        try {
            tsr = connector.getTSResponse(tsq, server);
        } catch (IOException | TSPException e) {
            logger.catching(e);
            return;
        }
        logger.debug("TSA response received");

        // log reason of failure
        if (tsr.getFailInfo() != null) {
            connector.logFailReason(tsr.getFailInfo().intValue());
            return;
        }

        // log response
        connector.logResponse(tsr);

        // get name
        /*=== Temporary UI start ===*/
        System.out.println();
        System.out.print("Save response as: ");
        String saveName = sc.nextLine();
        System.out.println();
        /*=== Temporary UI end ===*/

        // save response to file
        try {
            connector.saveToFile(saveName, tsr.getEncoded());
            logger.info("TimeStamp Response successfully saved as: {}", saveName);
        } catch (IOException e) {
            logger.error("Save to file '{}' failed.", saveName);
            logger.catching(e);
        }
        logger.exit();
    }

    /**
     * returns the ASN.1 OID of the given hash algorithm
     *
     * @param algorithm {@link org.bouncycastle.crypto.Digest} hash algorithm name
     * @return the ASN.1 OID of the given hash algorithm
     * @throws IllegalArgumentException when unsupported algorithm is chosen
     */
    private ASN1ObjectIdentifier getHashObjectIdentifier(final String algorithm) throws IllegalArgumentException {
        switch (algorithm) {
            case "MD5":
                return TSPAlgorithms.MD5;
            case "SHA-1":
                return TSPAlgorithms.SHA1;
            case "SHA-224":
                return TSPAlgorithms.SHA224;
            case "SHA-256":
                return TSPAlgorithms.SHA256;
            case "SHA-384":
                return TSPAlgorithms.SHA384;
            case "SHA-512":
                return TSPAlgorithms.SHA512;
            default:
                throw new IllegalArgumentException(algorithm + " not a supported algorithm");
        }
    }

    /**
     * reads binary data of specified file
     *
     * @param filename file to be opened
     * @return file byte data
     * @throws IOException
     */
    private byte[] readFileByte(String filename) throws IOException {
        Path path = Paths.get(filename);

        return Files.readAllBytes(path);
    }

    /**
     * computes digest hash using specified algorithm
     *
     * @param message       base from which the digest will be computed (i.e. file to be stamped)
     * @param messageDigest algorithm used to calculate the digest
     * @return calculated digest
     */
    private byte[] calculateMessageDigest(byte[] message, ExtendedDigest messageDigest) {
        messageDigest.update(message, 0, message.length); // offset - '0' means start from the beginning
        // digest obviously has to be computed from whole message
        byte[] digest = new byte[messageDigest.getDigestSize()];
        int size = messageDigest.doFinal(digest, 0); // offset - '0' means start from the beginning

        // return only valid part of digest (can be shorter than maximum digest size)
        return Arrays.copyOfRange(digest, 0, size); // offset - '0' means start from the beginning
    }

    /**
     * generates TS request with following definition
     * <p>
     * The TimeStampReq ASN.1 type definition:
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
     * @param digest     digest calculated using some hashing algorithm
     * @param requestAlg algorithm specification for {@link TimeStampRequestGenerator}
     *                   it has to correspond to algorithm used to calculate @param digest
     * @return TimeStamp Request as defined above
     */
    private TimeStampRequest getTSRequest(byte[] digest, ASN1ObjectIdentifier requestAlg) {
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();

        return tsqGenerator.generate(requestAlg, digest);
    }

    /**
     * sends TS Request and receives an answer in following definition
     * <p>
     * The TimeStampResp ASN.1 type definition:
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
     *
     * @param tsq    TimeStamp Request to be sent to TSA
     * @param server complete URL of the TSA server
     * @return TimeStamp Response created from TSA's response
     */
    private TimeStampResponse getTSResponse(TimeStampRequest tsq, String server) throws IOException, TSPException {
        logger.trace("entering getTSResponse() method");
        logger.entry(tsq, server);
        final byte[] request = tsq.getEncoded();
        // open valid connection
        HttpURLConnection con;
        try {
            URL url = new URL(server);
            con = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            logger.error("TSA server couldn't be contacted");
            throw e;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestProperty("Content-type", "application/timestamp-query");
        con.setRequestProperty("Content-length", String.valueOf(request.length));
        logger.info("TSA server was successfully contacted");

        // send request
        OutputStream out;
        try {
            out = con.getOutputStream();
            out.write(request);
            out.flush();
        } catch (IOException e) {
            logger.error("Failed to send the TS request.");
            throw e;
        }
        logger.debug("TS request sent");

        // receive response
        InputStream in;
        TimeStampResp resp;
        TimeStampResponse response;
        try {
            // verify connection status
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            } else {
                logger.debug("Response Code: {}", con.getResponseCode());
            }
            // accept the answer
            in = con.getInputStream();
            resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            response = new TimeStampResponse(resp);
            // verify the answer
            response.validate(tsq);
        } catch (TSPException | IOException e) {
            logger.error("Cannot interpret incoming data.");
            throw e;
        }

        logger.debug("Status: {}", response.getStatusString()); // null means OK

        return logger.exit(response);
    }

    /**
     * prints reason of failure according to <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> standard
     *
     * @param reason intValue given by TSA server
     */
    private void logFailReason(final int reason) {
        switch (reason) {
            case 0: {
                logger.error("unrecognized or unsupported Algorithm Identifier");
                return;
            }

            case 2: {
                logger.error("transaction not permitted or supported");
                return;
            }

            case 5: {
                logger.error("the data submitted has the wrong format");
                return;
            }

            case 14: {
                logger.error("the TSA's time source is not available");
                return;
            }

            case 15: {
                logger.error("the requested TSA policy is not supported by the TSA");
                return;
            }
            case 16: {
                logger.error("the requested extension is not supported by the TSA");
                return;
            }

            case 17: {
                logger.error("the additional information requested could not be understood or is not available");
                return;
            }

            case 25: {
                logger.error("the request cannot be handled due to system failure");
                return;
            }

            default: {
                logger.error("Unknown error occurred! Error code ({}) not specified in RFC 3161 standard.", reason);
            }
        }
    }

    /**
     * prints details of received TimeStamp
     *
     * @param tsr {@link TimeStampResponse}
     */
    private void logResponse(final TimeStampResponse tsr) {
        logger.info("Timestamp: {}", tsr.getTimeStampToken().getTimeStampInfo().getGenTime());
        logger.info("TSA: {}", tsr.getTimeStampToken().getTimeStampInfo().getTsa());
        logger.info("Serial number: {}", tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber());
        logger.info("Policy: {}", tsr.getTimeStampToken().getTimeStampInfo().getPolicy());
    }

    /**
     * saves byte data to specified file
     *
     * @param filename save file
     * @param data     binary data
     * @throws IOException
     */
    private void saveToFile(final String filename, final byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }
}
