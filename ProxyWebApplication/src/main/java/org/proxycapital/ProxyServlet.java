package org.proxycapital;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.proxycapital.EB5.exceptions.EB5Exceptions;
import org.proxycapital.EB5.registration.RegisterOrganization;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.Properties;

@javax.servlet.annotation.WebServlet(name = "/servlets/ProxyServlet")
public class ProxyServlet extends javax.servlet.http.HttpServlet {

    private static final Log logger = LogFactory.getLog(ProxyServlet.class);
    private static String SECRET = "mysecret";
    private static String REGISTRARROLES_ORDERER = "peer,client";
    private static String REGISTRARROLES_PEER = "peer,client,orderer";
    private static String ADMIN_ATTRIBUTES = "read,write,modify"; //These are the attributes that the admin can set
    // for users that he is registering.
    private static String CA_CERT_FILE_NAME = "ca-cert.pem";
    private static String CA_CERT_FILE_PATH = FileUtils.getUserDirectoryPath() + File.separator + "fabric-ca" + File
            .separator + "server";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
                                                                                           IOException {
        doGet(request, response);
        logger.debug("Inside Post");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)  {
        logger.debug("Inside the servlet!!");
//        String caName = request.getParameter("caName");
        String caName="localhost";
//        String caURL = request.getParameter("caURL");
        String caURL="http://localhost:7054";
//        String orgName = request.getParameter("orgName");
        String orgName="ProxyCapital";
//        String projectName = request.getParameter("projectName");
        String projectName=null;
        PrintWriter writer=null;
        try {
            setup(caName, caURL, orgName, projectName);
            writer=response.getWriter();
            writer.println(responseHTML());
        }
        catch (EB5Exceptions e) {
            logger.debug(e.getMessage());
            writer.println(responseHTML(e.getMessage()));
        }
        catch (IOException e) {
            logger.debug(e.getMessage());
            writer.println(responseHTML(e.getMessage()));
        }


    }
    private String responseHTML(String e){
        String response = "<html>";
        response += "<h2>"+e+"</h2>";
        response += "</html>";
        return response;
    }
    private String responseHTML(){
        String response = "<html>";
        response += "<h2>Registration successfully completed </h2>";
        response += "</html>";
        return response;
    }

    private void setup(String caName, String caURL, String orgName, String projectName) throws EB5Exceptions {
        boolean orderer = true;
        Properties props = new Properties();
        File certFile = Paths.get(CA_CERT_FILE_PATH + File
                .separator + CA_CERT_FILE_NAME).toFile();
        if(!certFile.exists()){
            certFile=Paths.get("/home/bitnami/fabric-ca/server/" + File.separator+CA_CERT_FILE_NAME).toFile();//Check in alternate location!!
        }
        logger.debug("The file path is: " + certFile.getAbsolutePath());
        props.setProperty("pemFile", certFile.getAbsolutePath());
        props.setProperty("allowAllHostNames", "true");
        logger.debug("The new property is : " + props.getProperty("allowAllHostNames"));
        logger.debug("The property file path is: " + props.get("pemFile"));
        Organization org = new Organization(orgName, orgName, caName, caURL, props);
        OrganizationUser admin = new OrganizationUser("Admin@" + orgName.toUpperCase(), orgName);
        org.setHasOrderer(true);
        org.setPeerCount(2);
        admin.setMspId(org.getMspID());
        admin.setEnrollmentSecret(SECRET);
        admin.setAffiliation(org.getName());
        if (!orderer) {
            admin.addAttribute("hf.Registrar.Roles",
                               REGISTRARROLES_ORDERER); //Can generateMSP only Peer and Clients and not Orderers.
            admin.addAttribute("hf.AffiliationMgr", "true");
        }
        else {
            admin.addAttribute("hf.Registrar.Roles",
                               REGISTRARROLES_PEER);
            admin.addAttribute("hf.AffiliationMgr", "true");
        }
        admin.addAttribute("hf.Registrar.Attributes", ADMIN_ATTRIBUTES);
        org.setAdminUser(admin);
        OrganizationUser user1 = new OrganizationUser("user1", org.getName());
        user1.setMspId(org.getMspID());
        user1.setEnrollmentSecret(SECRET);
//        user1.setAffiliation(org.getName());
        user1.addAttribute("read", "true");
        user1.addAttribute("write", "true");
        user1.addAttribute("modify", "false");
        org.addUser(user1);
        OrganizationUser user2 = new OrganizationUser("user2", org.getName());
        user2.setMspId(org.getMspID());
        user2.setEnrollmentSecret(SECRET);
//        user2.setAffiliation(org.getName());
        user2.addAttribute("read", "true");
        user2.addAttribute("write", "false");
        user2.addAttribute("modify", "false");
        org.addUser(user2);
        RegisterOrganization registerOrganization = null;
        try {
            //todo Change Host Name to a user provided value. Need to change the html file also.
            registerOrganization = new RegisterOrganization(certFile,
                                                            true,
                                                            org,
                                                            caName,
                                                            caURL,
                                                            caName,
                                                            projectName);
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
