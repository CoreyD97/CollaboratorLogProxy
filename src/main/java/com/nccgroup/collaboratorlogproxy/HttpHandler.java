package com.nccgroup.collaboratorlogproxy;

import com.google.gson.*;
import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpHandler implements HttpRequestHandler {

    private static Logger logger = LogManager.getLogger("CollaboratorLogging");
    private final String actualAddress;
    private final Integer actualPort;
    private final boolean actualIsHttps;

    public HttpHandler(String actualAddress, Integer actualPort, boolean actualIsHttps){
        this.actualAddress = actualAddress;
        this.actualPort = actualPort;
        this.actualIsHttps = actualIsHttps;
    }

    private CloseableHttpClient buildHttpClient() {
        HttpClientBuilder httpClientBuilder =
                HttpClients.custom()
                        .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                        .setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(5000).build())
                        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE); //Don't hang around!

        return httpClientBuilder.build();
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context) {

        try (CloseableHttpClient client = buildHttpClient()) {

            String requestURI = request.getRequestLine().getUri();
            boolean isPolling = requestURI.startsWith("/burpresults?biid=");
            String id;
            if(isPolling){
                id=URLDecoder.decode(requestURI.substring("/burpresults?biid=".length()), StandardCharsets.UTF_8.name());
            }else{
                id="";
            }

            HttpInetConnection connection = (HttpInetConnection) context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
            InetAddress clientAddress = connection.getRemoteAddress();

            //Make request to actual collaborator server
            URI forwardingURI = new URL((actualIsHttps ? "https://" : "http://") + actualAddress + ":" + actualPort
                    + requestURI).toURI();

            HttpUriRequest forwardingRequest = RequestBuilder.copy(request).setUri(forwardingURI).build();
            if(!isPolling) {
                forwardingRequest.addHeader("X-Collaborator-Proxy-For", clientAddress.getHostAddress());
            }

            HttpResponse actualRequestResponse = client.execute(forwardingRequest);

            String actualResponse = IOUtils.toString(actualRequestResponse.getEntity().getContent());

            for (Header header : actualRequestResponse.getAllHeaders()) {
//                if (header.getName().startsWith("X-Collaborator") || header.getName().startsWith("Server")) {
                if (!header.getName().startsWith("Content-Length")){// || header.getName().startsWith("Server")) {
                    response.addHeader(header);
                }
            }

            if (actualRequestResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                if(isPolling && !actualResponse.equalsIgnoreCase("{}")){
                    try{
                        JsonObject responseObject = JsonParser.parseString(actualResponse).getAsJsonObject();
                        JsonArray responses = responseObject.get("responses").getAsJsonArray();
                        for (JsonElement element : responses) {
                            JsonObject elementObj = element.getAsJsonObject();
                            String protocol = elementObj.get("protocol").getAsString();
                            if(protocol.equalsIgnoreCase("http") || protocol.equalsIgnoreCase("https")){
                                JsonObject dataObj = elementObj.getAsJsonObject("data");
                                byte[] requestBytes = Base64.getDecoder().decode(dataObj.get("request").getAsString());
                                String requestString = new String(requestBytes, StandardCharsets.ISO_8859_1);
                                Pattern p = Pattern.compile("X-Collaborator-Proxy-For:(.*)\r\n");
                                Matcher m = p.matcher(requestString);
                                if(m.find()){
                                    String ip = m.group(1).trim();
                                    requestString = m.replaceAll("");

                                    String base64Request = Base64.getEncoder().encodeToString(requestString.getBytes(StandardCharsets.ISO_8859_1));
                                    dataObj.addProperty("request", base64Request);
                                    elementObj.addProperty("client", ip);
                                }
                            }
                        }

                        actualResponse = new Gson().toJson(responseObject);
                    }catch (Exception e){
                        logger.error(e);
                    }

                    logger.info(String.format("[POLLING] IP: %s, ID: %s, Body: %s", clientAddress, id, actualResponse));
                }
            }

            response.setEntity(new StringEntity(actualResponse));
        } catch (Exception e) {
//            Log exception?
            logger.error(e);
            response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
