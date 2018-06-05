package org.proxycapital.EB5.registration;

import com.google.gson.JsonObject;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.*;
import org.hyperledger.fabric_ca.sdk.exception.AffiliationException;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InfoException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.lightcouch.CouchDbClient;
import org.lightcouch.CouchDbProperties;
import org.proxycapital.EB5.Utils.Utils;
import org.proxycapital.Organization;
import org.proxycapital.OrganizationUser;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

public class RegisterOrganization {
    private static final int DB_PORT = 5984;
    private static final int MAX_CONNECTIONS = 100;
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "password";
    private static final Log logger = LogFactory.getLog(RegisterOrganization.class);
    private static final String ORDERER_HOME = System.getProperty("user.home") + "/cryptoconfig/ordererOrganizations";
    private static final String PEER_HOME = System.getProperty("user.home") + "/cryptoconfig/peerOrganizations";
    private static final String DB_NAME = "userdb";
    private static final String DB_PROTOCOL = "http";
    private static final String DB_HOST = "127.0.0.1";
    private boolean isTLSEnabled = false;
    private final Properties props = new Properties();
    private final File userHomeDir = FileUtils.getUserDirectory();
    private File cryptoDir = null;
    private Organization org = null;
    private Enrollment bootstrapAdminEnrollment = null;
    private String caURL = null;
    private String caName = null;
    private String caHostName = null;
    private String serverCert = null;
    private OrganizationUser bootstrapAdmin = null;
    private CouchDbClient dbClient = null;
    private final CouchDbProperties couchDbProperties = new CouchDbProperties();

    /**
     * Use when TLS is enabled
     *
     * @param certFile
     * @param isTLSEnabled
     * @throws EB5Exceptions
     */
    public RegisterOrganization(
            File certFile, boolean isTLSEnabled, Organization org, String caName, String caURL,
            String caHostName)
            throws EB5Exceptions {
        this.isTLSEnabled = isTLSEnabled;
        this.org = org;
        this.caURL = caURL;
        this.caName = caName;
        this.caHostName = caHostName;
        initDB();
        if (isTLSEnabled && !certFile.exists()) {
            throw new EB5Exceptions("Certificate File missing");
        }
        else {
            props.setProperty("pemFile", certFile.getAbsolutePath());
        }
        Utils.createDirectory(userHomeDir.getAbsolutePath(), "cryptoconfig");
        cryptoDir = new File(userHomeDir.getAbsolutePath() + "/" + "cryptoconfig");
        setupDirectories();
        try {
            if (isTLSEnabled) {
                serverCert = FileUtils.readFileToString(certFile);
            }
            else {
                serverCert = org.getClient().info().getCACertificateChain();
//                serverCert = getServerCertificate();
            }
        }
        catch (IOException | InfoException | InvalidArgumentException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    /**
     * Use this constructor when TLS is disabled.
     */
    public RegisterOrganization(Organization org, String caURL, String caHostName) throws EB5Exceptions {
        this.isTLSEnabled = false;
        this.org = org;
        this.caURL = caURL;
        this.caHostName = caHostName;
        initDB();
        Utils.createDirectory(userHomeDir.getAbsolutePath(), "cryptoconfig");
        cryptoDir = new File(userHomeDir.getAbsolutePath() + "/" + "cryptoconfig");
        setupDirectories();
        try {
            serverCert = org.getClient().info().getCACertificateChain();
        }
        catch (InfoException | InvalidArgumentException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
//        serverCert = getServerCertificate();
    }

    private void initDB() {
        couchDbProperties.setDbName(DB_NAME);
        couchDbProperties.setProtocol(DB_PROTOCOL);
        couchDbProperties.setHost(DB_HOST);
        couchDbProperties.setUsername(USERNAME);
        couchDbProperties.setPassword(PASSWORD);
        couchDbProperties.setPort(DB_PORT);
        couchDbProperties.setMaxConnections(MAX_CONNECTIONS);
        couchDbProperties.setCreateDbIfNotExist(true);
        dbClient = new CouchDbClient(couchDbProperties);
    }

    private void setupDirectories() throws EB5Exceptions {
        if (org == null) {
            throw new EB5Exceptions("Organization has not been initialized. Please initialize the organization");
        }
        else {
            if (org.hasOrderer()) {
                Utils.createDirectory(cryptoDir.getAbsolutePath(), "ordererOrganizations");
                createOrgMSPStructure(cryptoDir.getAbsolutePath() + "/ordererOrganizations", "Orderer");
            }
            if (org.hasPeers()) {
                Utils.createDirectory(cryptoDir.getAbsolutePath(), "peerOrganizations");
                createOrgMSPStructure(cryptoDir.getAbsolutePath() + "/peerOrganizations", "Peer");
            }
        }
    }

    /**
     * Creates MSP structure at the organization level.
     *
     * @param path
     * @param type
     * @throws EB5Exceptions
     */
    private void createOrgMSPStructure(String path, String type) throws EB5Exceptions {
        Utils.createDirectory(path, org.getName());
        if (type.equals("Orderer")) {
            File ordererHome = new File(path + "/" + org.getName());
            Utils.createDirectory(ordererHome.getAbsolutePath(), "orderers");
            Utils.createDirectory(ordererHome.getAbsolutePath(), "ca");
            Utils.createDirectory(ordererHome.getAbsolutePath(), "msp");
            Utils.createDirectory(ordererHome.getAbsolutePath(), "users");
        }
        if (type.equals("Peer")) {
            File peerHome = new File(path + "/" + org.getName());
            Utils.createDirectory(peerHome.getAbsolutePath(), "peers");
            Utils.createDirectory(peerHome.getAbsolutePath(), "ca");
            Utils.createDirectory(peerHome.getAbsolutePath(), "msp");
            Utils.createDirectory(peerHome.getAbsolutePath(), "users");
        }
    }

    /**
     * Gets the servers certificate. Useful only for non TLS connections.
     *
     * @return
     * @throws EB5Exceptions
     */
    private String getServerCertificate() throws EB5Exceptions {
        String hostname = caHostName;
        SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
        SSLSocket socket;
        try {
            socket = (SSLSocket) factory.createSocket(hostname, 7054);
            socket.startHandshake();
            Certificate[] certs = socket.getSession().getPeerCertificates();
            Certificate cert = certs[0];
            PublicKey key = cert.getPublicKey();
            StringWriter pemsWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(pemsWriter);
            pemWriter.writeObject(key);
            logger.debug("The server public key is: " + pemsWriter.toString());
            socket.close();
            pemWriter.flush();
            pemWriter.close();
            return pemsWriter.toString();
        }
        catch (IOException e) {
            logger.debug(e.getMessage());
            logger.debug("cert likely not found in keystore, will pull cert...");
        }
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "changeit".toCharArray();
            ks.load(null, password);
            SSLContext context = SSLContext.getInstance("TLS");
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[]{tm}, null);
            factory = context.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(hostname, 7054);
            try {
                socket.startHandshake();
            }
            catch (SSLException e) {
                //we should get to here
            }
            X509Certificate[] chain = tm.chain;
            if (chain == null) {
                System.out.println("Could not obtain server certificate chain");
                return null;
            }
            X509Certificate cert = chain[0];
            String alias = hostname;
            ks.setCertificateEntry(alias, cert);
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.close();
            return sw.toString();
        }
        catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    /**
     * Create folder structure for msps.
     *
     * @param path
     * @param userName
     * @param enrollment
     * @throws EB5Exceptions
     */
    private void createMSPStructure(String path, String userName, Enrollment enrollment) throws EB5Exceptions {
        BufferedWriter bw, bw1;
        bw = bw1 = null;
        Utils.createDirectory(path + "/users/", userName);
        Utils.createDirectory(path + "/users/" + userName, "msp");
        String mspPath = path + "/users/" + userName + "/msp";
        String keyStorePath = mspPath + "/keystore";
        Utils.createDirectory(mspPath, "signcerts");
        Utils.createDirectory(mspPath, "keystore");
        Utils.createDirectory(mspPath, "cacerts");
        try {
            bw = new BufferedWriter(new FileWriter(mspPath + "/signcerts/cert.pem"));
            String certPEM = bootstrapAdminEnrollment.getCert();
            bw.write(certPEM);
            bw1 = new BufferedWriter(new FileWriter(keyStorePath + "/" + userName + "_sk"));
            StringWriter pemsWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(pemsWriter);
            pemWriter.writeObject(enrollment.getKey());
            pemWriter.flush();
            pemWriter.close();
            bw1.write(pemsWriter.toString());
            if (serverCert != null) {
                String caCertFileName = mspPath + "/cacerts/ca-cert.pem";
                File caCertFileDest = new File(caCertFileName);
                FileWriter fw = new FileWriter(caCertFileDest);
                fw.write(serverCert);
                fw.flush();
                fw.close();
            }
            else {
                throw new EB5Exceptions("Unable to  fetch Server certificate");
            }
//            File caCertFileSource=new File()
        }
        catch (IOException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
        finally {
            try {
                if (bw != null) {
                    bw.close();
                }
                if (bw1 != null) {
                    bw1.close();
                }
            }
            catch (IOException e) {
                logger.debug(e.getMessage());
                throw new EB5Exceptions(e.getMessage());
            }
        }
        Utils.createDirectory(mspPath, "cacerts");
        Utils.createDirectory(mspPath, "keystore");
        Utils.createDirectory(mspPath, "intermediatecerts");
    }

    public boolean isTLSEnabled() {
        return isTLSEnabled;
    }

    public void setTLSEnabled(boolean TLSEnabled) {
        isTLSEnabled = TLSEnabled;
    }

    private void generateMSPForUsers(String path) throws EB5Exceptions {
        if (bootstrapAdminEnrollment == null) {
            throw new EB5Exceptions("Boot Strap Admin not enrolled");
        }
        else {
            if (org.getAdminUser() == null) {
                throw new EB5Exceptions("Org admin not set");
            }
            else {
                createMSPStructure(path, "rootAdmin", bootstrapAdminEnrollment);
                Enrollment nodeAdminEnrollment = registerAndEnrollUser(org.getAdminUser(), bootstrapAdmin);
                if (nodeAdminEnrollment != null) {
                    createMSPStructure(path, org.getAdminUser().getName(), nodeAdminEnrollment);
                }
            }
        }
        //Generate MSP for all the users
        Map<String, OrganizationUser> userMap = org.getUserMap();
        for (final String userName : userMap.keySet()) {
            OrganizationUser user = userMap.get(userName);
            Enrollment nodeAdminEnrollment = org.getAdminUser().getEnrollment();
            if (nodeAdminEnrollment == null) {
                throw new EB5Exceptions("Org Admin is not enrolled");
            }
            else {
                Enrollment userEnrollment = registerAndEnrollUser(user, org.getAdminUser());
                if (userEnrollment != null) {
                    createMSPStructure(path, user.getName(), userEnrollment);
                }
                else {
                    logger.debug("Unable to register user: " + user.getName());
                    throw new EB5Exceptions("Unable to register user");
                }
            }
        }

    }

    public void generateMSP() throws EB5Exceptions {
        try {
            HFCAClient caClient = HFCAClient.createNewInstance(caName, caURL, props);
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            org.setCAClient(caClient);
            caClient.newHFCAAffiliation("cts");
            enrollBootStrapAdmin();
            try {
                logger.debug("Affiliations are: " + caClient.getHFCAAffiliations(bootstrapAdmin).getName());
            }
            catch (AffiliationException e) {
                logger.debug(e.getMessage());
                throw new EB5Exceptions(e.getMessage());
            }
            if (org.hasOrderer()) {
                String path = ORDERER_HOME + "/" + org.getName();
                generateMSPForUsers(path);
            }
            if (org.hasPeers()) {
                String path = PEER_HOME + "/" + org.getName();
                createMSPStructure(path, "rootAdmin", bootstrapAdminEnrollment);
                generateMSPForUsers(path);
            }
        }
        catch (MalformedURLException e) {
            logger.error("Wrong URL specified: " + caURL);
            throw new EB5Exceptions(e.getMessage());
        }
        catch (InvalidArgumentException e) {
            logger.debug(e.getStackTrace());
            throw new EB5Exceptions(e.getMessage());
        }
        catch (InstantiationException e) {
            logger.debug("Error in creating cryptosuite");
            throw new EB5Exceptions(e.getMessage());
        }
        catch (InvocationTargetException | IllegalAccessException | org.hyperledger.fabric.sdk.exception.InvalidArgumentException | NoSuchMethodException | CryptoException | ClassNotFoundException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private void enrollBootStrapAdmin() throws EB5Exceptions {
        bootstrapAdmin = new OrganizationUser("admin", org.getName());
        bootstrapAdmin.setMspId(org.getMspID());
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.addHost(caURL);
        try {
            bootstrapAdmin.setAffiliation(org.getName());
            bootstrapAdminEnrollment = org.getClient().enroll(bootstrapAdmin.getName(), "adminpw");
            bootstrapAdmin.setEnrollment(bootstrapAdminEnrollment);
        }
        catch (EnrollmentException | InvalidArgumentException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private Enrollment registerAndEnrollUser(OrganizationUser registreeUser, OrganizationUser registrar) throws
                                                                                                         EB5Exceptions {
        boolean isRegistered = false;
        HFCAIdentity id;
        try {
            Collection identities = org.getClient().getHFCAIdentities(registrar);
            for (final Object identity : identities) {
                id = (HFCAIdentity) identity;
                if (id.getEnrollmentId().equals(registreeUser.getName())) {
                    isRegistered = true;
                }
            }
            if (!isRegistered) {
                RegistrationRequest rr = new RegistrationRequest(registreeUser.getName(),
                                                                 registreeUser.getAffiliation());
                if (registreeUser.getAttributes() != null) {
                    for (final Object o : registreeUser.getAttributes().entrySet()) {
                        Map.Entry pair = (Map.Entry) o;
                        rr.addAttribute(new Attribute(pair.getKey().toString(), pair.getValue().toString()));
                    }
                }
                Enrollment enrollment = org.getClient().enroll(registreeUser.getName(),
                                                               org.getClient().register(rr, registrar));
                registreeUser.setEnrollment(enrollment);
                saveState(registreeUser);
                return enrollment;
            }
            else {
//                org.proxycapital.OrganizationUser u=dbClient.find(org.proxycapital.OrganizationUser.class,"4791ca3983054bf8a23cd20527a23140");
                OrganizationUser u = restoreState(registreeUser.getName());
               // logger.debug("The enrollment cert is: " + u.getEnrollment().getCert());
                return u.getEnrollment();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private void saveState(OrganizationUser user) throws EB5Exceptions {
        if (!dbClient.contains(user.getName())) {
            JsonObject json = new JsonObject();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                json.addProperty("_id", user.getName());
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                oos.writeObject(user);
                oos.flush();
//            keyValStore.setValue(keyValStoreName, Hex.toHexString(bos.toByteArray()));
                json.addProperty("enrollment", Hex.toHexString(bos.toByteArray()));
                dbClient.save(json);
                bos.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        else {
            throw new EB5Exceptions("User not found in local database. Please contact administrator");
        }
    }

    /**
     * Restore the state of this user from the key value store (if found).  If not found, do nothing.
     */
    private OrganizationUser restoreState(String uid) {
        JsonObject json = dbClient.find(JsonObject.class, uid);
        if (null != json) {
            // The user was found in the key value store, so restore the
            // state.
            String enrollmentString = json.get("enrollment").getAsString();
            byte[] serialized = Hex.decode(enrollmentString);
            ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                OrganizationUser state = (OrganizationUser) ois.readObject();
                if (state != null) {
                    return state;
                }
            }
            catch (Exception e) {
                throw new RuntimeException("Could not restore state of member", e);
            }
        }
        return null;
    }

    private static class SavingTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
