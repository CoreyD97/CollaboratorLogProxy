package com.nccgroup.collaboratorlogproxy;

import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.appender.RollingFileAppender;
import org.apache.logging.log4j.core.appender.rolling.SizeBasedTriggeringPolicy;
import org.apache.logging.log4j.core.appender.rolling.TimeBasedTriggeringPolicy;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.layout.PatternLayout;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.io.*;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class CollaboratorLogProxy {

    public static Logger logger = LogManager.getRootLogger();
    private static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    private static final String COLLABORATOR_SERVER_ADDRESS = "collaborator_server_address";
    private static final String COLLABORATOR_HTTP_SERVER_PORT = "collaborator_http_server_port";
    private static final String COLLABORATOR_HTTPS_SERVER_PORT = "collaborator_https_server_port";
    private static final String LOG_PROXY_HTTP_SERVER_PORT = "log_proxy_http_server_port";
    private static final String LOG_PROXY_HTTPS_SERVER_PORT = "log_proxy_https_server_port";
    private static final String PRIVATE_KEY_PATH = "ssl_private_key_path";
    private static final String CERTIFICATE_PATH = "ssl_certificate_path";
    private static final String INTERMEDIATE_CERTIFICATE_PATH = "ssl_intermediate_certificate_path";
    private static final String INTERMEDIATE_CERTIFICATE_DEFAULT = "/certs/intermediate.crt";
    private static final String LOG_LEVEL = "log_level";
    private static final String LOG_DIR = "log_directory";
    private static final String ROLLING_LOGS = "rolling_logs";

    private HttpServer httpServer;
    private HttpServer httpsServer;

    private CollaboratorLogProxy(org.apache.commons.configuration2.Configuration properties) throws Exception {

        String actualAddress = properties.getString(COLLABORATOR_SERVER_ADDRESS);
        Integer actualHTTPPort = properties.getInt(COLLABORATOR_HTTP_SERVER_PORT);
        Integer actualHTTPSPort = properties.getInt(COLLABORATOR_HTTPS_SERVER_PORT);

        InetAddress listenAddress = InetAddress.getByName("0.0.0.0");


        logger.info("Starting server in HTTPS mode. Creating SSL context.");
        SSLContext sslContext;
        //Load private key
        logger.info("Loading private key from file: " + properties.getProperty(PRIVATE_KEY_PATH));
        PrivateKey privateKey = Utilities.loadPrivateKeyFromFile(properties.getString(PRIVATE_KEY_PATH));

        ArrayList<Certificate> certificateList = new ArrayList<>();
        //Load certificate
        logger.info("Loading certificate from file: " + properties.getProperty(CERTIFICATE_PATH));
        certificateList.add(Utilities.loadCertificateFromFile(properties.getString(CERTIFICATE_PATH)));
        //Load intermediate certificate
        String intermediatePath = properties.getString(INTERMEDIATE_CERTIFICATE_PATH);
        if(!StringUtils.isEmpty(intermediatePath) && !intermediatePath.equals(INTERMEDIATE_CERTIFICATE_DEFAULT)){
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
                .setListenerPort(properties.getInt(LOG_PROXY_HTTP_SERVER_PORT))
                .setLocalAddress(listenAddress)
                .setExceptionLogger(ex -> {
                    logger.debug(ex);
                })
                .registerHandler("*", new HttpHandler(actualAddress, actualHTTPPort, false)).create();


        httpsServer = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setListenerPort(properties.getInt(LOG_PROXY_HTTPS_SERVER_PORT))
                .setLocalAddress(listenAddress)
                .setExceptionLogger(ex -> {
                    logger.debug(ex);
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
        return SSLContexts.custom().loadKeyMaterial(keyStore, password).loadTrustMaterial(new TrustAllStrategy()).build();
    }

    public static void main(String[] args) throws Exception {

        FileBasedConfigurationBuilder<PropertiesConfiguration> configBuilder;
        org.apache.commons.configuration2.Configuration config;

        if(args.length == 0){
            //Create default properties file
            File defaultsFile = new File("LogProxy.properties");
            if(defaultsFile.exists()){
                logger.error("Could not create the defaults file. File exists.");
                logger.error("Start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`" +
                        " or remove the file to allow it to be populated with the defaults");
                return;
            }

            InputStream defaultsResource = CollaboratorLogProxy.class.getClassLoader().getResourceAsStream("LogProxy.properties");
            Files.copy(defaultsResource, Path.of(defaultsFile.toURI()));


            logger.warn("Default config written to " + defaultsFile.getName());
            logger.warn("Edit the config, then start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`");
            return;
        }else{
            File configFile = new File(args[0]);
            if(!configFile.exists()){
                logger.error("Config file does not exist. Run the jar without arguments to generate the default config.");
                return;
            }else{
                configBuilder = new Configurations().propertiesBuilder(configFile);
                config = configBuilder.getConfiguration();

                //Setup log file
                Level logLevel = Level.valueOf(config.getString(LOG_LEVEL));
                Configurator.setRootLevel(logLevel);

                LoggerContext context = (LoggerContext) LogManager.getContext(false);
                Configuration logConfig = context.getConfiguration();

                PatternLayout logLayout = PatternLayout.newBuilder()
                        .withConfiguration(logConfig)
                        .withPattern("[%-5level] %d{yyyy-MM-dd HH:mm:ss} %msg%n")
                        .build();

                if(config.getBoolean(ROLLING_LOGS)){
                    RollingFileAppender fileAppender = RollingFileAppender.newBuilder()
                            .setName("Rolling File Appender")
                            .withFileName(config.getString(LOG_DIR) + "/LogProxy.log")
                            .withFilePattern(config.getString(LOG_DIR) + "/$${date:yyyy-MM}/LogProxy-%d{yyyy-MM-dd}-%i.log.gz")
                            .withPolicy(TimeBasedTriggeringPolicy.newBuilder().withInterval(1).build())
                            .setConfiguration(logConfig)
                            .setLayout(logLayout)
                            .build();
                    fileAppender.start();
                    context.getConfiguration().getRootLogger().addAppender(fileAppender, logLevel, null);
                }else{
                    FileAppender fileAppender = FileAppender.newBuilder()
                            .setName("File Appender")
                            .withFileName(new File(config.getString(LOG_DIR) + "/LogProxy.log").getAbsolutePath())
                            .setConfiguration(logConfig)
                            .setLayout(logLayout)
                            .build();
                    fileAppender.start();
                    context.getConfiguration().getRootLogger().addAppender(fileAppender, logLevel, null);
                }

                context.updateLoggers();
            }
        }

        try {
            CollaboratorLogProxy server = new CollaboratorLogProxy(config);
            server.start();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
