package org.commonjava.util.http.client;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.AbstractHttpClient;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLManager;

public interface ClientConfigurator
{

    void configure( AbstractHttpClient client )
        throws HTTPException;

    ClientConnectionManager createConnectionManager( SSLManager sslManager )
        throws HTTPException;

}
