package com.cesnet.pki.tsa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.tsp.*;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;

/**
 * Status: Beta
 * <p>
 * doublecheck <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a> compliance
 * <p>
 * Created by Petr Vsetecka on 3. 2. 2016.
 */
public class TSAConnector {
    private static final Logger logger = LogManager.getLogger();
    public final String server = "http://tsa.cesnet.cz:3161/tsa";
//    public final String server = "https://tsa-dev.cesnet.cz:8442/signserver/tsa?workerName=TimeStampSigner";
    
    // <editor-fold defaultstate="collapsed" desc="legacy main method for testing purposes">
    //
    public static void main(String[] args) throws IOException, TSPException, Exception {
        TSAConnector connector = new TSAConnector();

//        if (args.length != 2) {
//            connector.showHelp();
//            return;
//        }
//
//        String filename = args[0];
//        String saveName = args[1];

//        TimeStampResponse tsr = connector.parseTSR(connector.readFileByte("D:\\Downloads\\achjo_png-stamp.tsr"));
//        TimeStampResponse tsr = connector.parseTSR(connector.readFileByte("/home/geralt/Desktop/cesnet/razitka-ukazka/ss_zaklad-stamp.tsr"));
//    byte[][] bytesArray = new byte[2][];
//    bytesArray[0] = new byte[]{1,2};
//    bytesArray[1] = connector.readFileByte("D:\\Downloads\\achjo_png-stamp.tsr");
//        System.out.println("i: "+connector.findTS(bytesArray));

//    connector.logResponse(tsr);
//        try {
//            connector.verify(new FileInputStream("D:\\MATLAB\\R2013a\\bin\\mex.bat"), new FileInputStream("C:\\Users\\Petr\\Downloads\\mex_bat-stamp.tsr"));
            System.out.println("--------------------------");
//            connector.verify(new FileInputStream("D:\\MATLAB\\R2013a\\bin\\mex.bat"), new FileInputStream("D:\\Dropbox\\cesnet\\Projekty\\TSA-Service\\uber-razitko.tsr"));
//        } catch (CertificateException | OperatorCreationException ex) {
//            java.util.logging.Logger.getLogger(TSAConnector.class.getName()).log(Level.SEVERE, null, ex);
//        }

    // method to save the timestamp
//    connector.saveToFile("fact.tsr", connector.stamp("mex.bat", connector.readFileByte("/mnt/1C88A3ED88A3C39C/factorio.txt")));

    // method to verify the timestamp
    connector.verify(connector.readFileByte("D:\\Dropbox\\cesnet\\razitka-ukazka\\ss_chain"), connector.readFileByte("D:\\Dropbox\\cesnet\\razitka-ukazka\\ss_chain-stamp.tsr"));
    }
    // */
    // </editor-fold>
    
    /**
     * Main method for stamping given file.
     * It serves as an example of whole process in one go.
     * 
     * @param filename
     * @param fileContent
     * @return  
     * @throws java.io.IOException 
     * @throws org.bouncycastle.tsp.TSPException 
     */
    public byte[] stamp(String filename, byte[] fileContent) throws IOException, TSPException {
        logger.entry();

        logger.info("File to be stamped: {}", filename);
//        byte[] file = getBytesFromInputStream(is);
        
        ExtendedDigest digestAlgorithm = new SHA256Digest(); // select hash algorithm
        ASN1ObjectIdentifier requestAlgorithm;
        try {
            requestAlgorithm = getHashObjectIdentifier(digestAlgorithm.getAlgorithmName());
        } catch (IllegalArgumentException e) {
            logger.catching(e);
            throw e;
        }
        logger.info("Selected algorithm: {}", digestAlgorithm.getAlgorithmName());

        // create request
        byte[] digest = calculateMessageDigest(fileContent, digestAlgorithm);
        TimeStampRequest tsq = getTSRequest(digest, requestAlgorithm);
        logger.debug("TS request generated");

        // send request and receive response
        TimeStampResponse tsr;
        try {
            tsr = getTSResponse(tsq, server);
        } catch (IOException | TSPException e) {
            logger.catching(e);
            throw e;
        }
        logger.debug("TSA response received");

        // log reason of failure
        if (tsr.getFailInfo() != null) {
            logFailReason(tsr.getFailInfo().intValue());
            return null;
        }

        // log response
        logResponse(tsr);

        logger.exit();
        return tsr.getEncoded();
    }
    
    /**
     * Main method for validating files with stamps.
     * It serves as an example of whole process in one go.
     * 
     * @param originalFile
     * @param timeStamp
     * @throws IOException
     * @throws TSPException
     * @throws CertificateException
     * @throws CertificateEncodingException
     * @throws OperatorCreationException 
     */
    public void verify(byte[] originalFile, byte[] timeStamp) throws IOException, TSPException, CertificateException, CertificateEncodingException, OperatorCreationException, CertificateExpiredException, CertificateNotYetValidException, CMSException {
        logger.entry();
        
        // open files
//        byte[] file = getBytesFromInputStream(originalFile);
        TimeStampResponse tsr = parseTSR(timeStamp);//getBytesFromInputStream(timeStamp));
        
        logger.info("The timestamp was sucessfully opened.");
        logResponse(tsr);
        
        // get hash algorithm
        ASN1ObjectIdentifier algID = tsr.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID();
        GeneralDigest digestAlgorithm = getDigestAlg(algID);
        
        logger.info("The timestamp's algorithm was recognized as {}.", digestAlgorithm.getAlgorithmName());
        
        // create new hashed request
        byte[] digest = calculateMessageDigest(originalFile, digestAlgorithm);
        TimeStampRequest tsq = getTSRequest(digest, algID);
        
        // compare hashes
        try {
            tsr.validate(tsq);
        } catch (TSPException e) {
            logger.catching(e);
            throw e;
        }
        
        logger.info("The timestamp fits the file (the file was not changed), now verifying certificates..");

        if (containsCertificate(tsr)) {
            // verify included certificate
            logger.info("Found certificates included in the Timestamp.");
            try {
                verifyCertificateIncluded(tsr.getTimeStampToken());
            } catch (CertificateExpiredException | CertificateNotYetValidException | CMSException e) {
                logger.catching(e);
                throw e;
            }
            
            logger.info("All certificates successfully verified, the timestamp is trusted.");
        } else {
            logger.info("No certificate found.");
        
            // verify certificate from external file
//            verifyCertificate(tsr, new FileInputStream("path\\to\\cert.pem"));
        }
        
        logger.exit();
    }
    
    /**
     * tells if the stamp contains some certificate
     * 
     * @param tsr
     * @return 
     */
    public boolean containsCertificate(TimeStampResponse tsr) {
        CollectionStore certs = (CollectionStore) tsr.getTimeStampToken().getCertificates();
        
        int certsCount = 0;
        for (Iterator it = certs.iterator(); it.hasNext(); it.next()) {
            certsCount++; // stupid hack to get actual number of certificates
        }
        
        if (certsCount < 1) {
            return false;
        }
        
        return true;
    }
    
    public void verifyCertificateIncluded(TimeStampToken tst) throws CertificateExpiredException, CertificateNotYetValidException, CMSException, OperatorCreationException, CertificateException {
        // get certificates
        CollectionStore certs = (CollectionStore) tst.getCertificates();
        SignerInformationStore signers = tst.toCMSSignedData().getSignerInfos();
        
        for (SignerInformation signer : signers) {
            Collection<X509CertificateHolder> col = certs.getMatches(signer.getSID());
            
            if (col.size() == 1) {
                logger.error("Expected only one certificate per signer.");
                throw new CertificateException("Expected only one certificate per signer.");
            }
            
            X509Certificate signCert = new JcaX509CertificateConverter().getCertificate(col.stream().findAny().get());
            
            signCert.checkValidity();
            
            signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signCert)); // should verify that the timestamp is signed correctly
        }
    }
    
    /**
     * verifies if the TSR was generated by TSA using given certificate
     * 
     * @param tsr
     * @param certStream
     * @throws CertificateException
     * @throws IOException
     * @throws CertificateEncodingException
     * @throws OperatorCreationException
     * @throws TSPException 
     */
    public void verifyCertificateFile(TimeStampResponse tsr, InputStream certStream)
            throws CertificateException, IOException, CertificateEncodingException, OperatorCreationException, TSPException {
        
        CertificateFactory factory;
        X509Certificate cert;
        try {
            factory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) factory.generateCertificate(certStream);
        } catch (CertificateException e) {
            logger.catching(e);
            throw e;
        }

        //RSA Signature processing with BC
        X509CertificateHolder holder;
        SignerInformationVerifier siv;
        try {
            holder = new X509CertificateHolder(cert.getEncoded());
            siv = new BcRSASignerInfoVerifierBuilder(
                    new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(),
                    new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(holder);
        } catch (CertificateEncodingException | OperatorCreationException e) {
            logger.catching(e);
            throw e;
        }

        //Signature processing with JCA and other provider
        //X509CertificateHolder holderJca = new JcaX509CertificateHolder(cert);
        //SignerInformationVerifier sivJca = new JcaSimpleSignerInfoVerifierBuilder().setProvider("anotherprovider").build(holderJca);

        try {
            tsr.getTimeStampToken().validate(siv);
        } catch (TSPException e) {
            logger.catching(e);
            throw e;
        }
    }
    
    public Pair findTS(byte[][] files) {
        int i = 0;
        TimeStampResponse tsr = null;
        for (byte[] file : files) {
            try {
                tsr = parseTSR(file);
                break;
            } catch (Exception e) {
                //logger.catching(e);
                i++;
            }
        }
        return new Pair(tsr, files[1-i]);
    }
    
    /**
     * creates TimeStampResponse object
     * 
     * @param timeStamp
     * @return
     * @throws IOException
     * @throws TSPException 
     */
    public TimeStampResponse parseTSR(byte[] timeStamp) throws IOException, TSPException {
        TimeStampResponse tsr;
        try {
            tsr = new TimeStampResponse(timeStamp);
        } catch (TSPException e) {
            logger.catching(e);
            throw e;
        }
        
        return tsr;
    }
    
    /**
     * identifies supported algorithm
     * 
     * @param algID
     * @return 
     */
    public GeneralDigest getDigestAlg(ASN1ObjectIdentifier algID) {
        if (algID.equals(TSPAlgorithms.SHA1)) {
            return new SHA1Digest();
        } else if (algID.equals(TSPAlgorithms.SHA256)) {
            return new SHA256Digest();
        } else {
            IllegalArgumentException e = new IllegalArgumentException("Selected timestamp was not created using supported (SHA-1 or SHA-256) algorithm.");
            logger.catching(e);
            throw e;
        }
    }
    
    /**
     * method for JSP to create valid TimeStampRequest
     * 
     * @param file
     * @param tsr
     * @return 
     */
    public TimeStampRequest createCorrespondingTSQ(byte[] file, TimeStampResponse tsr) {
        // get hash algorithm
        ASN1ObjectIdentifier algID = tsr.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID();
        GeneralDigest digestAlgorithm = getDigestAlg(algID);
        
        logger.info("The timestamp's algorithm was recognized as {}.", digestAlgorithm.getAlgorithmName());
        
        // create new hashed request
        byte[] digest = calculateMessageDigest(file, digestAlgorithm);
        TimeStampRequest tsq = getTSRequest(digest, algID);
        
        return tsq;
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
                IllegalArgumentException e = new IllegalArgumentException(algorithm + " not a supported algorithm");
                logger.catching(e);
                throw e;
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
     * converts InputStream to byte array
     * 
     * @param is
     * @return
     * @throws IOException 
     */
    public byte[] getBytesFromInputStream(InputStream is) throws IOException {
        try (ByteArrayOutputStream os = new ByteArrayOutputStream();)
        {
            byte[] buffer = new byte[0xFFFF];

            for (int len; (len = is.read(buffer)) != -1;)
                os.write(buffer, 0, len);

            os.flush();

            return os.toByteArray();
        }
    }

    /**
     * computes digest hash using specified algorithm
     *
     * @param message       base from which the digest will be computed (i.e. file to be stamped)
     * @param messageDigest algorithm used to calculate the digest
     * @return calculated digest
     */
    protected byte[] calculateMessageDigest(byte[] message, ExtendedDigest messageDigest) {
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
        
        tsqGenerator.setCertReq(true); // OVERIT!!!! melo by zpusobit, ze ve vydanem razitku bude pritomny retez certifikatu

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
        //con.setRequestProperty("Content-length", String.valueOf(request.length));
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
        logger.error("TSA server returned error");
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
                logger.error("unknown error - error code ({}) not corresponding to RFC 3161 standard.", reason);
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
    public void saveToFile(final String filename, final byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    /**
     * text displayed when wrong number of arguments provided
     */
    private void showHelp() {
        logger.error("wrong number of arguments");
        logger.error("obligatory arguments: filename_input filename_output");
        logger.error("example: java -jar TSAConnector.jar file.in file.out");

    }

    public class Pair {
        public TimeStampResponse tsr;
        public byte[] msg;

        public Pair(TimeStampResponse tsr, byte[] msg) {
            this.tsr = tsr;
            this.msg = msg;
        }
    }
}
