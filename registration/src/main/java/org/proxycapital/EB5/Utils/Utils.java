package org.proxycapital.EB5.Utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.proxycapital.EB5.registration.RegisterOrganization;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import java.io.File;
import java.io.IOException;

public class Utils {
    private static final Log logger = LogFactory.getLog(RegisterOrganization.class);

    /**
     * Creates a directory in path mentioned by path1
     *
     * @param path1
     * @param dirName
     */

    public static void createDirectory(String path1, String dirName) throws EB5Exceptions {
        File homeDir = new File(path1);
        logger.debug("HomeDir is : " + homeDir.getAbsolutePath());
        String targetDirPath = homeDir.getAbsolutePath() + "/" + dirName;
        logger.debug("Target Dir is: "+ targetDirPath);
        File targetDir = new File(targetDirPath);
        try {
            if (!FileUtils.directoryContains(homeDir, targetDir)) {
                FileUtils.forceMkdir(targetDir);
            }
        } catch (IOException e) {
            logger.debug(e.getMessage());
            throw new EB5Exceptions(e.getMessage());

        }
    }
}
