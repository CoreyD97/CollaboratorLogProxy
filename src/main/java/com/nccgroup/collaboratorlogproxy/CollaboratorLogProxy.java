package com.nccgroup.collaboratorlogproxy;

import nu.studer.java.util.OrderedProperties;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public class CollaboratorLogProxy {

    public static Logger logger = LogManager.getRootLogger();
    private static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    private static final String COLLABORATOR_SERVER_ADDRESS = "collaborator_server_address";
    private static final String COLLABORATOR_HTTP_SERVER_PORT = "collaborator_http_server_port";
    private static final String COLLABORATOR_HTTPS_SERVER_PORT = "collaborator_https_server_port";
    private static final String LISTEN_ADDRESS = "listen_address";
    private static final String PRIVATE_KEY_PATH = "ssl_private_key_path";
    private static final String CERTIFICATE_PATH = "ssl_certificate_path";
    private static final String INTERMEDIATE_CERTIFICATE_PATH = "ssl_intermediate_certificate_path";
    private static final String INTERMEDIATE_CERTIFICATE_DEFAULT = "/certs/intermediate.crt";
    private static final String LOG_LEVEL = "log_level";

    private HttpServer httpServer;
    private HttpServer httpsServer;

    private CollaboratorLogProxy(Properties properties) throws Exception {
        Level logLevel = Level.valueOf(properties.getProperty(LOG_LEVEL));
        Configurator.setRootLevel(logLevel);

        String actualAddress = properties.getProperty(COLLABORATOR_SERVER_ADDRESS);
        Integer actualHTTPPort = Integer.parseInt(properties.getProperty(COLLABORATOR_HTTP_SERVER_PORT));
        Integer actualHTTPSPort = Integer.parseInt(properties.getProperty(COLLABORATOR_HTTPS_SERVER_PORT));

        InetAddress listenAddress = InetAddress.getByName("0.0.0.0");


        logger.info("Starting server in HTTPS mode. Creating SSL context.");
        SSLContext sslContext;
        //Load private key
        logger.info("Loading private key from file: " + properties.getProperty(PRIVATE_KEY_PATH));
        PrivateKey privateKey = Utilities.loadPrivateKeyFromFile(properties.getProperty(PRIVATE_KEY_PATH));

        ArrayList<Certificate> certificateList = new ArrayList<>();
        //Load certificate
        logger.info("Loading certificate from file: " + properties.getProperty(CERTIFICATE_PATH));
        certificateList.add(Utilities.loadCertificateFromFile(properties.getProperty(CERTIFICATE_PATH)));
        //Load intermediate certificate
        String intermediatePath = properties.getProperty(INTERMEDIATE_CERTIFICATE_PATH);
        if(!intermediatePath.equals("") && !intermediatePath.equals(INTERMEDIATE_CERTIFICATE_DEFAULT)){
            logger.info("Loading intermediate certificate from file: " + properties.getProperty(INTERMEDIATE_CERTIFICATE_PATH));
            certificateList.add(Utilities.loadCertificateFromFile(intermediatePath));
        }
        Certificate[] certificateChain = certificateList.toArray(new Certificate[0]);

        //Create new keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, DEFAULT_KEYSTORE_PASSWORD.toCharArray());
        keyStore.setKeyEntry("collaboratorAuth", privateKey,
                DEFAULT_KEYSTORE_PASSWORD.toCharArray(), certificateChain);
//                keyStore.
        sslContext = createSSLContext(keyStore, DEFAULT_KEYSTORE_PASSWORD.toCharArray());

        httpServer = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setListenerPort(80)
                .setLocalAddress(listenAddress)
                .setExceptionLogger(ex -> {
                    if(ex instanceof SSLException){
                        logger.error("Client Connection Failed: " + ex.getMessage());
                    }else{
                        logger.error(ex);
                    }
                })
                .registerHandler("*", new HttpHandler(actualAddress, actualHTTPPort, false)).create();


        httpsServer = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setListenerPort(443)
                .setLocalAddress(listenAddress)
                .setExceptionLogger(ex -> {
                    if(ex instanceof SSLException){
                        logger.error("Client Connection Failed: " + ex.getMessage());
                    }else{
                        logger.error(ex);
                    }
                })
                .setSslContext(sslContext)
                .registerHandler("*", new HttpHandler(actualAddress, actualHTTPSPort, true)).create();
    }

    public void start() throws IOException {
        if(httpServer != null) {
            httpServer.start();
            logger.info("Server started. Listening for poll requests on port " + httpServer.getLocalPort() + "...");
            Runtime.getRuntime().addShutdownHook(new Thread(() -> httpServer.shutdown(500, TimeUnit.MILLISECONDS)));
        }

        if(httpsServer != null) {
            httpsServer.start();
            logger.info("Server started. Listening for poll requests on port " + httpsServer.getLocalPort() + "...");
            Runtime.getRuntime().addShutdownHook(new Thread(() -> httpsServer.shutdown(500, TimeUnit.MILLISECONDS)));
        }
    }

    private SSLContext createSSLContext(final KeyStore keyStore, final char[] password) throws Exception {
        return SSLContexts.custom().loadKeyMaterial(keyStore, password).build();
    }

    public static void main(String[] args) throws Exception {

        OrderedProperties properties = getDefaultProperties();
        if(args.length == 0){
            //Create default properties file
            File defaultsFile = new File("LogProxy.properties");
            if(defaultsFile.exists()){
                logger.error("Could not create the defaults file. File exists.");
                logger.error("Start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`" +
                        " or remove the file to allow it to be populated with the defaults");
                return;
            }
            FileOutputStream outputStream = new FileOutputStream(defaultsFile);
            properties.store(outputStream, "MAKE SURE THE SECRET IS CHANGED TO SOMETHING MORE SECURE!\n" +
                    "By default, the private key and certificates will be used to\n" +
                    "configure the SSL context. To use a keystore instead, comment out " + PRIVATE_KEY_PATH + ".");
            logger.info("Default config written to " + defaultsFile.getName());
            logger.info("Edit the config (especially the secret!)");
            logger.info("Then start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`");
            return;
        }else{
            File configFile = new File(args[0]);
            if(!configFile.exists()){
                logger.error("Config file does not exist. Run the jar without arguments to generate the default config.");
                return;
            }else{
                try (FileInputStream inputStream = new FileInputStream(configFile)) {
                    properties.load(inputStream);
                }
            }
        }

        try {
            CollaboratorLogProxy server = new CollaboratorLogProxy(properties.toJdkProperties());
            server.start();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static OrderedProperties getDefaultProperties(){
        OrderedProperties defaultProperties = new OrderedProperties.OrderedPropertiesBuilder()
                .withSuppressDateInComment(true).build();
        defaultProperties.setProperty(COLLABORATOR_SERVER_ADDRESS, "127.0.0.1");
        defaultProperties.setProperty(COLLABORATOR_HTTP_SERVER_PORT, "81");
        defaultProperties.setProperty(COLLABORATOR_HTTPS_SERVER_PORT, "444");
        defaultProperties.setProperty(LISTEN_ADDRESS, "0.0.0.0");
        defaultProperties.setProperty(PRIVATE_KEY_PATH, "/certs/key.pem.pkcs8");
        defaultProperties.setProperty(CERTIFICATE_PATH, "/certs/cert.crt");
        defaultProperties.setProperty(INTERMEDIATE_CERTIFICATE_PATH, INTERMEDIATE_CERTIFICATE_DEFAULT);
        defaultProperties.setProperty(LOG_LEVEL, "INFO");

        return defaultProperties;
    }
}
