package org.commonjava.util.http.client;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLManager;

public class DefaultClientConfigurator
    implements ClientConfigurator
{

    @Override
    public void configure( final AbstractHttpClient client )
        throws HTTPException
    {
        // NOP
    }

    @Override
    public ClientConnectionManager createConnectionManager( final SSLManager sslManager )
        throws HTTPException
    {
        final PoolingClientConnectionManager ccm = new PoolingClientConnectionManager();
        configureConnectionManager( ccm );

        final SSLSocketFactory socketFactory = sslManager.getSSLSocketFactory();
        final SchemeRegistry registry = ccm.getSchemeRegistry();

        // TODO: Allow configuration of ssl ports? How do we detect those, or should we allow them to be added on the fly?
        registry.register( new Scheme( "https", 443, socketFactory ) );

        return ccm;
    }

    protected void configureConnectionManager( final PoolingClientConnectionManager ccm )
    {
        ccm.setMaxTotal( 20 );
    }

}
