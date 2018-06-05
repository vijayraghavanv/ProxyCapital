package tests;

import org.proxycapital.Organization;
import org.proxycapital.OrganizationUser;
import org.proxycapital.EB5.registration.RegisterOrganization;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import java.io.File;
import java.nio.file.Paths;

public class EnrollmentTest {
    private static boolean orderer=false;
    public static void main(String[] args) {
        Organization org = new Organization("cts", "cts");
        OrganizationUser admin = new OrganizationUser("Admin@CTS", "cts");
        admin.setMspId("cts");
        admin.setEnrollmentSecret("mysecret");
        admin.setAffiliation(org.getName());
        if(!orderer) {
            admin.addAttribute("hf.Registrar.Roles",
                               "peer,client"); //Can generateMSP only Peer and Clients and not Orderers.
            admin.addAttribute("hf.AffiliationMgr","true");
        }
        else{
            admin.addAttribute("hf.Registrar.Roles",
                               "peer,client,orderer");
            admin.addAttribute("hf.AffiliationMgr","true");
        }
        admin.addAttribute("hf.Registrar.Attributes","read,write,modify");
        org.setAdminUser(admin);
        File certFile = Paths.get("/Users/vijay/OneDrive/UpWork/ca-cert.pem").toFile();
        OrganizationUser user1 = new OrganizationUser("user1", "cts");
        user1.setMspId("cts");
        user1.setEnrollmentSecret("mysecret");
        user1.setAffiliation(org.getName());
        user1.addAttribute("read","true");
        user1.addAttribute("write","true");
        user1.addAttribute("modify","false");
        org.addUser(user1);
        OrganizationUser user2 = new OrganizationUser("user2", "cts");
        user2.setMspId("cts");
        user2.setEnrollmentSecret("mysecret");
        user2.setAffiliation(org.getName());
        user2.addAttribute("read","true");
        user2.addAttribute("write","false");
        user2.addAttribute("modify","false");
        org.addUser(user2);
        RegisterOrganization registerOrganization = null;
        try {
            registerOrganization = new RegisterOrganization(certFile,
                                                            true,
                                                            org,
                                                            "ProxyRoot",
                                                            "https://blockchain001:7054",
                                                            "blockchain001");
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
