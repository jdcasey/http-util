package org.commonjava.util.http.ssl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.commonjava.util.http.HTTPException;

@ApplicationScoped
public class SSLManager
{

    @Inject
    private SSLProvider builder;

    private SSLSocketFactory factory;

    public SSLManager()
    {
    }

    public SSLManager( final SSLProvider builder )
    {
        this.builder = builder;
    }

    public SSLSocketFactory setupSSL()
        throws HTTPException
    {
        final SSLSocketFactory factory = getSSLSocketFactory();

        SSLContext ctx;
        try
        {
            ctx = SSLContext.getInstance( "SSL" );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to retrieve SSLContext: %s", e, e.getMessage() );
        }

        try
        {
            ctx.init( new KeyManager[] { builder.getKeyManager() }, new TrustManager[] { builder.getTrustManager() },
                      null );
        }
        catch ( final KeyManagementException e )
        {
            throw new HTTPException( "Failed to initialize SSLContext with new PEM-based TrustStore: %s", e,
                                     e.getMessage() );
        }

        SSLContext.setDefault( ctx );

        return factory;
    }

    @Produces
    @Default
    public synchronized SSLSocketFactory getSSLSocketFactory()
        throws HTTPException
    {
        if ( factory == null )
        {
            factory = builder.build();
        }

        return factory;
    }
}
