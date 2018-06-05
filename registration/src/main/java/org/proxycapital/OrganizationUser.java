package org.proxycapital;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class OrganizationUser implements User, Serializable {
    private static final long serialVersionUID = -5878483208339508919L;
    private Enrollment enrollment = null;
    private String name;
    private Set<String> roles;
    private String account;
    private String affiliation;
    private String organization;
    private String enrollmentSecret;
    private String mspId;

    public Map<String, String> getAttributes() {
        return attributes;
    }

    private Map<String, String> attributes=new HashMap<>();

    public OrganizationUser(String name, String org) {
        this.name = name;
        this.organization = org;
    }
    public void addAttribute(String attributeName, String attributeValue){
        attributes.put(attributeName,attributeValue);
    }
    public String getAttribute(String attributeName){
        return attributes.get(attributeName);
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    @Override
    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    @Override
    public String getAffiliation() {
        return affiliation;
    }

    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
    }

    @Override
    public Enrollment getEnrollment() {
        return enrollment;
    }

    public void setEnrollment(Enrollment enrollment) {
        this.enrollment = enrollment;
    }

    public String getEnrollmentSecret() {
        return enrollmentSecret;
    }

    public void setEnrollmentSecret(String enrollmentSecret) {
    }

    @Override
    public String getMspId() {
        return mspId;
    }

    public void setMspId(String mspID) {
        this.mspId = mspID;
    }
}
