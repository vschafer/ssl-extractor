/* Copyright 2012-2013 Vladimir Schäfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fi.schafer.sslextractor;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Class can be invoked from command line and extract certificates provided by remote party at an SSL/TLS port.
 * Certificates are stored both as .cer files and imported into a .jks Java keystore.
 */
public class ExtractCertificate {

    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            System.out.println("Usage: java -jar sslextractor.jar host port");
            System.exit(1);
        }

        String host = args[0];
        Integer port = Integer.valueOf(Integer.parseInt(args[1]));

        final List certs = new ArrayList();

        X509TrustManager trust = new X509TrustManager() {

            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                System.out.println(s);
            }

            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                for (int i = 0; i < x509Certificates.length; i++) {
                    X509Certificate cert = x509Certificates[i];
                    System.out.println("Loading certificate " + cert.getSubjectDN() + " issued by: " + cert.getIssuerDN());
                    certs.add(x509Certificates[i]);
                }
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trust}, null);
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port.intValue());

        socket.getInputStream();
        socket.getSession().getPeerCertificates();
        socket.close();

        Iterator iterator = certs.iterator();
        while (iterator.hasNext()) {
            X509Certificate cert = (X509Certificate) iterator.next();
            String outputFile = cert.getSubjectDN().getName().replaceAll("[^a-zA-Z0-9-=_\\.]", "_") + ".cer";
            System.out.println("Serializing certificate to: " + outputFile);
            FileOutputStream certfos = new FileOutputStream(outputFile);
            certfos.write(cert.getEncoded());
            certfos.close();
        }

    }

}