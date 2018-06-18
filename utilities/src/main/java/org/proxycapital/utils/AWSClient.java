
package org.proxycapital.utils;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.proxycapital.EB5.exceptions.EB5Exceptions;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class AWSClient {
    private static final Log logger = LogFactory.getLog(AWSClient.class);
    //todo Create webservice that will provide accesskey and secretkey
    private static final String accessKey="AKIAJ6HCHLBR6A6VM7GA";
    private static final String secretKey="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";
    private static final String S3BucketName="proxycapital.crypto";
    private static final String zipDirName= FileUtils.getUserDirectoryPath()+"/crypto.zip";
    private static final Regions region=Regions.US_EAST_2;
    public static void zipAndStoreInS3(File file, String keyName, HashMap metadataMap){

        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                                                 .withRegion(region)
                                                 .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                                                 .build();
        zipDirectory(file);
        PutObjectRequest request = new PutObjectRequest(S3BucketName, keyName, new File(zipDirName));
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentType("application/zip");
        if(metadataMap!=null){
            Iterator keySetItr=metadataMap.keySet().iterator();
            String metadataName;
            String metadataValue;
            while(keySetItr.hasNext()){
                metadataName=keySetItr.next().toString();
                metadataValue=metadataMap.get(metadataName).toString();
                metadata.addUserMetadata(metadataName,metadataValue);
            }


        }
        request.setMetadata(metadata);
        s3Client.putObject(request);
    }

    private static void zipDirectory(File file) {
        zipDirectory(file,zipDirName);
    }

    /**
     * Zips a file or folder. If it is a folder all the files except those that have extension of .key are zipped. \n
     * The zipped file is stored in the home directory as specified by zipDirName
     * @param dir
     * @param zipFileName The name of the zip file
     */
    private static void zipDirectory(File dir, String zipFileName) {
        try {
            List<String> filesListInDir=new ArrayList<String>();
            populateFilesList(dir,filesListInDir);

            //now zip files one by one
            //create ZipOutputStream to write to the zip file

            File zipFile=new File(zipFileName);
            boolean result = Files.deleteIfExists(zipFile.toPath());
            FileOutputStream fos = new FileOutputStream(zipFileName);
            ZipOutputStream zos = new ZipOutputStream(fos);
            for(String filePath : filesListInDir){
                logger.debug("Zipping "+filePath);
                //for ZipEntry we need to keep only relative file path, so we used substring on absolute path
                ZipEntry ze = new ZipEntry(filePath.substring(dir.getAbsolutePath().length()+1, filePath.length()));
                zos.putNextEntry(ze);
                //read the file and write to ZipOutputStream
                FileInputStream fis = new FileInputStream(filePath);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = fis.read(buffer)) > 0) {
                    zos.write(buffer, 0, len);
                }
                zos.closeEntry();
                fis.close();
            }
            zos.close();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * Returns folder list contents as a List of elements with their absolute paths. Omits private keys stored in the format of .key
     * @param dir Directory that needs to be scanned
     * @param filesListInDir List that needs to be populated with elements of @dir
     * @throws IOException
     */
    private static void populateFilesList(File dir, final List<String> filesListInDir) throws IOException {

        File[] files = dir.listFiles();
        if (files != null) {
            for(File file : files){
                if(file.isFile()) {
                    if(!StringUtils.equalsIgnoreCase(getFileExtension(file),"key")) {
                        filesListInDir.add(file.getAbsolutePath());
                    }
                }
                else populateFilesList(file, filesListInDir);
            }
        }

    }

    /**
     * Gets extension of file
     * @param file
     * @return
     */
    private static String getFileExtension(File file) {
        String fileName = file.getName();
        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
            return fileName.substring(fileName.lastIndexOf(".")+1);
        else return "";
    }
    public static void listAllObjects(String bucketName) throws EB5Exceptions {
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                                                     .withRegion(region)
                                                     .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                                                     .build();

            System.out.println("Listing objects");

            // maxKeys is set to 2 to demonstrate the use of
            // ListObjectsV2Result.getNextContinuationToken()
            ListObjectsV2Request req = new ListObjectsV2Request().withBucketName(bucketName).withMaxKeys(100);
            ListObjectsV2Result result;

            do {
                result = s3Client.listObjectsV2(req);

                for (S3ObjectSummary objectSummary : result.getObjectSummaries()) {
                    System.out.printf(" - %s (size: %d)\n", objectSummary.getKey(), objectSummary.getSize());
                }
                // If there are more than maxKeys keys in the bucket, get a continuation token
                // and list the next objects.
                String token = result.getNextContinuationToken();
                System.out.println("Next Continuation Token: " + token);
                req.setContinuationToken(token);
            } while (result.isTruncated());
        }
        catch(AmazonServiceException e) {
            // The call was transmitted successfully, but Amazon S3 couldn't process
            // it, so it returned an error response.
            if(StringUtils.equalsIgnoreCase(e.getErrorCode(),"AccessDenied")){
                throw new EB5Exceptions("User doesn't have privilege to view objects in the bucket.");
            }

        }
        catch(SdkClientException e) {
            // Amazon S3 couldn't be contacted for a response, or the client
            // couldn't parse the response from Amazon S3.
           throw new EB5Exceptions(e.getMessage());
        }


    }
}
