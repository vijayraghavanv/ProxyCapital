package org.proxycapital.web;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.proxycapital.EB5.exceptions.EB5Exceptions;
import org.proxycapital.EB5.registration.RegisterOrganization;
import org.proxycapital.Organization;
import org.proxycapital.OrganizationUser;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

@WebServlet(name = "/servlets/register")
public class UserRegistration extends HttpServlet {
    private static String SECRET="mysecret";
    private static String REGISTRARROLES_ORDERER="peer,client";
    private static String REGISTRARROLES_PEER="peer,client,orderer";
    private static String ADMIN_ATTRIBUTES="read,write,modify"; //These are the attributes that the admin can set for users that he is registering.
    private static String CA_CERT_FILE_NAME="ca-cert.pem";
    private static String CA_CERT_FILE_PATH=FileUtils.getUserDirectoryPath();
    private static final Log logger = LogFactory.getLog(UserRegistration.class);
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGet(request,response);
        logger.debug("Inside Post");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.debug("Inside the servlet!!");
        String caName=request.getParameter("caName");
        String caURL=request.getParameter("caURL");
        String orgName=request.getParameter("orgName");
        try {
            setup(caName,caURL,orgName);
        }
        catch (EB5Exceptions e) {
            logger.debug(e.getMessage());
        }
    }
    private void setup(String caName, String caURL, String orgName) throws EB5Exceptions {
        boolean orderer = false;
        Properties props=new Properties();
        File certFile = Paths.get(CA_CERT_FILE_PATH+File.separator+CA_CERT_FILE_NAME).toFile();
        props.setProperty("pemFile",certFile.getAbsolutePath());
        props.setProperty("allowAllHostNames","true");
        logger.debug("The new property is : " + props.getProperty("allowAllHostNames"));

        logger.debug("The property file path is: " + props.get("pemFile"));
        Organization org = new Organization(orgName, orgName, caName, caURL,props);
        OrganizationUser admin = new OrganizationUser("Admin@"+orgName.toUpperCase(), orgName);
        org.setPeerCount(2);
        admin.setMspId(org.getMspID());
        admin.setEnrollmentSecret(SECRET);
        admin.setAffiliation(org.getName());
        if(!orderer) {
            admin.addAttribute("hf.Registrar.Roles",
                               REGISTRARROLES_ORDERER); //Can generateMSP only Peer and Clients and not Orderers.
            admin.addAttribute("hf.AffiliationMgr","true");
        }
        else{
            admin.addAttribute("hf.Registrar.Roles",
                               REGISTRARROLES_PEER);
            admin.addAttribute("hf.AffiliationMgr","true");
        }
        admin.addAttribute("hf.Registrar.Attributes",ADMIN_ATTRIBUTES);
        org.setAdminUser(admin);

        OrganizationUser user1 = new OrganizationUser("user1", org.getName());
        user1.setMspId(org.getMspID());
        user1.setEnrollmentSecret(SECRET);
        user1.setAffiliation(org.getName());
        user1.addAttribute("read","true");
        user1.addAttribute("write","true");
        user1.addAttribute("modify","false");
        org.addUser(user1);
        OrganizationUser user2 = new OrganizationUser("user2", org.getName());
        user2.setMspId(org.getMspID());
        user2.setEnrollmentSecret(SECRET);
        user2.setAffiliation(org.getName());
        user2.addAttribute("read","true");
        user2.addAttribute("write","false");
        user2.addAttribute("modify","false");
        org.addUser(user2);
        RegisterOrganization registerOrganization = null;
        try {
            //todo Change Host Name to a user provided value. Need to change the html file also.
            registerOrganization = new RegisterOrganization(certFile,
                                                            true,
                                                            org,
                                                            caName,
                                                            caURL,
                                                            "ProxyRoot");
        }
        catch (EB5Exceptions eb5Exceptions) {
            eb5Exceptions.printStackTrace();
        }
        try {
            if (registerOrganization != null) {
                registerOrganization.generateMSP();
            }
        }
        catch (EB5Exceptions eb5Exceptions) {
            eb5Exceptions.printStackTrace();
        }

    }
}
