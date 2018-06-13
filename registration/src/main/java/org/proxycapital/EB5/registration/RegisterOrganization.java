package org.proxycapital.EB5.registration;

import com.google.gson.JsonObject;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric_ca.sdk.*;
import org.hyperledger.fabric_ca.sdk.exception.AffiliationException;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InfoException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.lightcouch.CouchDbClient;
import org.lightcouch.CouchDbProperties;
import org.lightcouch.NoDocumentException;
import org.proxycapital.EB5.Utils.Utils;
import org.proxycapital.EB5.exceptions.EB5Exceptions;
import org.proxycapital.Organization;
import org.proxycapital.OrganizationUser;

import java.io.*;
import java.util.*;

public class RegisterOrganization {
    private static final int DB_PORT = 5984;
    private static final int MAX_CONNECTIONS = 100;
    private static final String DB_USERNAME = "admin";
    private static final String DB_PASSWORD = "password";
    private static final Log logger = LogFactory.getLog(RegisterOrganization.class);
    private static final String ORDERER_HOME = System.getProperty("user.home") + "/cryptoconfig/ordererOrganizations";
    private static final String PEER_HOME = System.getProperty("user.home") + "/cryptoconfig/peerOrganizations";
    private static final String DB_NAME = "userdb";
    private static final String DB_PROTOCOL = "http";
    private static final String DB_HOST = "127.0.0.1";
    private Properties props =null;
    private final File userHomeDir = FileUtils.getUserDirectory();
    private final CouchDbProperties couchDbProperties = new CouchDbProperties();
    private boolean isTLSEnabled = false;
    private File cryptoDir = null;
    private Organization org = null;
    private Enrollment bootstrapAdminEnrollment = null;
    private String caURL = null;
    private String caName = null;
    private String caHostName = null;
    private String serverCert = null;
    private OrganizationUser bootstrapAdmin = null;
    private CouchDbClient dbClient = null;

    /**
     * Register an Organization and generate MSPs for the org. A folder "cryptoconfig" is generated in the home
     * directory and \n
     * all artifacts are stored inside this folder.
     *
     * @param certFile     CA Server's certificate file. If TLS is enabled, it is assumed that the user has received
     *                     this from Proxy.  Pass null if tls is not enabled
     * @param isTLSEnabled Set to true if TLS is enabled
     * @throws EB5Exceptions
     */
    public RegisterOrganization(
            File certFile, boolean isTLSEnabled, Organization org, String caName, String caURL,
            String caHostName)
            throws EB5Exceptions {
        logger.debug("The CA Host Name is: " + caHostName);
        this.isTLSEnabled = isTLSEnabled;
        this.org = org;
        this.caURL = caURL;
        this.caName = caName;
        this.caHostName = caHostName;
        Utils.createDirectory(userHomeDir.getAbsolutePath(), "cryptoconfig");
        cryptoDir = new File(userHomeDir.getAbsolutePath() + File.separator + "cryptoconfig");
        initDB();
        if (certFile == null && !isTLSEnabled) {
            this.isTLSEnabled = false;
            try {
                //Read certificate from the client
                serverCert = org.getClient().info().getCACertificateChain();
            }
            catch (InfoException | InvalidArgumentException e) {
                logger.debug(e.getMessage());
                throw new EB5Exceptions(e.getMessage());
            }
        }
        else {
            if (isTLSEnabled && !certFile.exists()) {
                throw new EB5Exceptions("Certificate File missing");
            }
            else {
                props=org.getProps();
                try {
                    if (isTLSEnabled) {
//                        File file = new File("/home/bitnami/ca-chain.pem");

//                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//                        X509Certificate certificate=(X509Certificate) cf.generateCertificate(new ByteArrayInputStream(org.getClient().info().getCACertificateChain().getBytes()));
//                        byte[] buf = certificate.getEncoded();
//                        FileOutputStream os = new FileOutputStream(file);
//                        os.write(buf);
//                        os.close();
//                        Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
//                        wr.write(new sun.misc.BASE64Encoder().encode(buf));
//                        wr.flush();
                        serverCert = FileUtils.readFileToString(certFile);
                    }
                    else {
                        serverCert = org.getClient().info().getCACertificateChain();
                    }
                }
                catch ( InfoException | InvalidArgumentException | IOException e) {
                    logger.debug(e.getMessage());
                    throw new EB5Exceptions(e.getMessage());
                }
            }
        }
        setupDirectories();
    }

    /**
     * Initialize couchDB
     */
    private void initDB() {
        couchDbProperties.setDbName(DB_NAME);
        couchDbProperties.setProtocol(DB_PROTOCOL);
        couchDbProperties.setHost(DB_HOST);
        couchDbProperties.setUsername(DB_USERNAME);
        couchDbProperties.setPassword(DB_PASSWORD);
        couchDbProperties.setPort(DB_PORT);
        couchDbProperties.setMaxConnections(MAX_CONNECTIONS);
        couchDbProperties.setCreateDbIfNotExist(true);
        dbClient = new CouchDbClient(couchDbProperties);
    }

    /**
     * Set up directories under cryptoconfig.
     *
     * @throws EB5Exceptions
     */
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

    private void createTLSStructure(String path, String host, Enrollment enrollment) throws EB5Exceptions {
        BufferedWriter bw, bw1, bw2;
        String rootPath = path + "/" + host;
        try {
            FileUtils.forceMkdir(new File(rootPath + "/" + "tls"));
            FileUtils.forceMkdir(new File(rootPath + "/" + "msp"));
            FileUtils.forceMkdir(new File(rootPath + "/msp/" + "keystore"));
            FileUtils.forceMkdir(new File(rootPath + "/msp/" + "tlscacerts"));
            FileUtils.forceMkdir(new File(rootPath + "/msp/" + "signcerts"));
            FileUtils.forceMkdir(new File(rootPath + "/msp/" + "cacerts"));
            bw = new BufferedWriter(new FileWriter(rootPath + "/tls/server.crt"));
            bw1 = new BufferedWriter(new FileWriter(rootPath + "/tls/server.key"));
            bw2 = new BufferedWriter(new FileWriter(rootPath + "/msp/signcerts/" + host + "-cert.pem"));
            bw.write(enrollment.getCert());
            bw2.write(enrollment.getCert());
            StringWriter pemsWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(pemsWriter);
            pemWriter.writeObject(enrollment.getKey());
            pemWriter.flush();
            pemWriter.close();
            bw1.write(pemsWriter.toString());
            FileUtils.copyFile(new File(rootPath + "/tls/server.key"), new File(rootPath + "/msp/keystore/server.key"));
            storeCaCertFile(rootPath + "/msp/tlscacerts/tlsca." + org.getName() + "-cert.pem");
            storeCaCertFile(rootPath + "/msp/cacerts/" + org.getName() + "-cert.pem");
        }
        catch (IOException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private void storeCaCertFile(String path) throws EB5Exceptions {
        if (serverCert != null) {
            File caCertFile = new File(path);
            try {
                FileWriter fw = new FileWriter(caCertFile);
                fw.write(serverCert);
                fw.flush();
                fw.close();
            }
            catch (IOException e) {
                logger.debug(e.getMessage());
                throw new EB5Exceptions(e.getMessage());
            }
        }
        else {
            throw new EB5Exceptions("Unable to fetch server certificate");
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
        bw = null;
        bw1 = null;
        Utils.createDirectory(path + "/users/", userName);
        Utils.createDirectory(path + "/users/" + userName, "msp");
        String mspPath = path + "/users/" + userName + "/msp";
        String keyStorePath = mspPath + "/keystore";
        Utils.createDirectory(mspPath, "signcerts");
        Utils.createDirectory(mspPath, "keystore");
        Utils.createDirectory(mspPath, "cacerts");
        Utils.createDirectory(mspPath, "intermediatecerts");
        try {
            bw = new BufferedWriter(new FileWriter(mspPath + "/signcerts/" + userName + "cert.pem"));
            String certPEM = enrollment.getCert();
            bw.write(certPEM);
            bw1 = new BufferedWriter(new FileWriter(keyStorePath + "/" + userName + "_sk"));
            StringWriter pemsWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(pemsWriter);
            pemWriter.writeObject(enrollment.getKey());
            pemWriter.flush();
            pemWriter.close();
            bw1.write(pemsWriter.toString());
            storeCaCertFile(mspPath + "/cacerts/" + org.getName() + "-cert.pem");
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
                Enrollment nodeAdminEnrollment = registerAndEnrollUser(org.getAdminUser(), bootstrapAdmin);
                org.getAdminUser().setEnrollment(nodeAdminEnrollment);
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

    private void generateTLS(String path, List hosts, String orgParam) throws EB5Exceptions {
        EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
        enrollmentRequestTLS.setProfile("tls");
        for (final Object host : hosts) {
            enrollmentRequestTLS.addHost(host.toString());
        }
        try {
            Enrollment enrollment = org.getClient().enroll("admin", "adminpw", enrollmentRequestTLS);
            createTLSStructure(path, orgParam, enrollment);
        }
        catch (EnrollmentException | InvalidArgumentException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private void generateTLSForNodes() throws EB5Exceptions {
        String orgDir;
        if (org.hasOrderer()) {
            orgDir = ORDERER_HOME + "/" + org.getName();
            //Create ca root
            ArrayList<String> hosts = new ArrayList<>(2);
            hosts.add("root");
            hosts.add("root");
            generateTLS(orgDir, hosts, "ca");
            //End CA Root creation
            ArrayList<String> ordererHosts = new ArrayList<>(2);
            String ordererName = "orderer" + "." + org.getName();
            ordererHosts.add(ordererName);
            ordererHosts.add("orderer");
            String ordererOrgDir = orgDir + File.separator + "orderer";
            generateTLS(ordererOrgDir, ordererHosts, ordererName);
        }
        if (org.hasPeers()) {
            orgDir = PEER_HOME + "/" + org.getName();
            //Create ca root
            ArrayList<String> hosts = new ArrayList<>(2);
            hosts.add("root");
            hosts.add("root");
            generateTLS(orgDir, hosts, "ca");
            //End CA Root creation
            int peerCount = org.getPeerCount();
            while (peerCount > 0) {
                peerCount--;
                ArrayList<String> peerHosts = new ArrayList<>(2);
                String peerName = "peer" + peerCount + "." + org.getName();
                peerHosts.add(peerName);
                peerHosts.add("peer" + peerCount);
                String peerOrgDir = orgDir + File.separator + "peers";
                generateTLS(peerOrgDir, peerHosts, peerName);
            }
        }
        //Generate CA Root tls
//        org.getClient().en
    }

    /**
     * Generates and stores the MSP data for the organization.
     *
     * @throws EB5Exceptions
     */
    public void generateMSP() throws EB5Exceptions {
        try {
            HFCAClient caClient = org.getClient();
            caClient.newHFCAAffiliation(org.getName());
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
                createMSPStructure(path,
                                   "rootAdmin",
                                   bootstrapAdmin.getEnrollment());//Create root admin under orderers.
                generateMSPForUsers(path);
            }
            if (org.hasPeers()) {
                String path = PEER_HOME + "/" + org.getName();
                createMSPStructure(path,
                                   "rootAdmin",
                                   bootstrapAdmin.getEnrollment()); //Create root admin under peer directory.
                generateMSPForUsers(path);
            }
            generateTLSForNodes();
        }
        catch (InvalidArgumentException e) {
            logger.debug(e.getStackTrace());
            throw new EB5Exceptions(e.getMessage());
        }
    }

    private void enrollBootStrapAdmin() throws EB5Exceptions {
        bootstrapAdmin = restoreState("admin");
        if (bootstrapAdmin == null) {
            bootstrapAdmin = new OrganizationUser("admin", org.getName());
            bootstrapAdmin.setMspId(org.getMspID());
            try {
                logger.debug("The certificate path is: " + props.getProperty("pemFile"));
                logger.debug("The certificate is: " + serverCert);

                bootstrapAdmin.setAffiliation(org.getName());
                bootstrapAdminEnrollment = org.getClient().enroll(bootstrapAdmin.getName(), "adminpw");
                bootstrapAdmin.setEnrollment(bootstrapAdminEnrollment);
            }
            catch (EnrollmentException | InvalidArgumentException e) {
                logger.debug(e.getMessage());
                throw new EB5Exceptions(e.getMessage());
            }
            saveState(bootstrapAdmin);
        }
        else {
            bootstrapAdminEnrollment = bootstrapAdmin.getEnrollment();
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
                OrganizationUser u = restoreState(registreeUser.getName());
                if (u != null) {
                    return u.getEnrollment();
                }
                else {
                    return null;
                }
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
            logger.info(new String("User  " + user.getName()+" exists in the database"));
        }
    }

    /**
     * Restore the state of this user from the key value store (if found).  If not found, do nothing.
     */
    private OrganizationUser restoreState(String uid) {
        JsonObject json = null;
        try {
            json = dbClient.find(JsonObject.class, uid);
        }
        catch (NoDocumentException e) {
            logger.debug(String.format("Object not found $s", uid));
        }
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
}
