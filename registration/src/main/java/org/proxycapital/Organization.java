package org.proxycapital;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class Organization {
    private final String name;
    private final String mspID;
    private boolean hasOrderer = false;
    private boolean hasPeers = true;
    private int peerCount = 0;
    private boolean isClient = false; //client will depend on peer for writing.
    private HFCAClient client;
    private Map<String, OrganizationUser> userMap = new HashMap<>();
    private OrganizationUser adminUser=null;

    public Properties getProps() {
        return props;
    }

    public void setProps(final Properties props) {
        this.props = props;
    }

    Properties props = null;

    public Organization(String name, String mspID, String caName, String caURL, Properties props) throws EB5Exceptions {
        this.name = name;
        this.mspID = mspID;
        this.props=props;
        HFCAClient caClient=null;

        try {
            caClient = HFCAClient.createNewInstance(caName, caURL, props);
            caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
//            caClient.newHFCAAffiliation(this.getName());
        }
        catch (IllegalAccessException | InstantiationException | ClassNotFoundException | CryptoException | InvalidArgumentException | NoSuchMethodException | InvocationTargetException | org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException | MalformedURLException e) {
            throw new EB5Exceptions(e.getMessage());
        }
        if(caClient !=null) {
            this.setCAClient(caClient);
        }
        else {
            throw new EB5Exceptions("Unable to set CA Client");
        }

    }


    public String getMspID() {
        return mspID;
    }

    public OrganizationUser getAdminUser() {
        return adminUser;
    }

    public void setAdminUser(final OrganizationUser adminUser) {
        this.adminUser = adminUser;
    }

    public String getName() {
        return name;
    }

    public boolean hasOrderer() {
        return hasOrderer;
    }

    public void setHasOrderer(boolean hasOrderer) {
        this.hasOrderer = hasOrderer;
    }

    public boolean hasPeers() {
        return hasPeers;
    }

    public void setHasPeers(boolean hasPeers) {
        this.hasPeers = hasPeers;
    }

    public boolean isClient() {
        return isClient;
    }

    public int getPeerCount() {
        return peerCount;
    }

    public void setPeerCount(int peerCount) {
        this.peerCount = peerCount;
    }

    public HFCAClient getClient() {
        return client;
    }

    public void setClient(boolean client) {
        isClient = client;
    }

    public void setCAClient(HFCAClient client) {
        this.client = client;
    }

    public Map<String, OrganizationUser> getUserMap() {
        return userMap;
    }

    public void setUserMap(Map<String, OrganizationUser> userMap) {
        this.userMap = userMap;
    }

    public void addUser(OrganizationUser user) {

        userMap.put(user.getName(), user);
    }

    public User getUser(String name) {

        return userMap.get(name);
    }

}
