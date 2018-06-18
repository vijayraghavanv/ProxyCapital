package org.proxycapital.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import java.io.File;
import java.util.Properties;

public class UtilsTest {
    private static final Log logger = LogFactory.getLog(UtilsTest.class);
    public static void main(String[] args) {
        File file =new File("/Users/vijay/cryptoconfig");

        try {
            AWSClient.zipAndStoreInS3(file,"cryptoconfig-walmart.zip",null);
            AWSClient.listAllObjects("proxycapital.crypto");
        }
        catch (EB5Exceptions e) {
            logger.debug(e.getMessage());
        }
    }
}
