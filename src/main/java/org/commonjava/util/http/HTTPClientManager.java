package org.commonjava.util.http;

import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.ContentEncodingHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.commonjava.util.http.ssl.SSLManager;

@ApplicationScoped
public class HTTPClientManager
{

    private HttpClient client;

    @Inject
    private SSLManager sslManager;

    @Inject
    private ClientConfigurator configurator;

    public HTTPClientManager()
    {
    }

    public HTTPClientManager( final SSLManager sslManager, final ClientConfigurator configurator )
        throws HTTPException
    {
        this.sslManager = sslManager;
        this.configurator = configurator;

        init();
    }

    @PostConstruct
    private void init()
        throws HTTPException
    {
        final ThreadSafeClientConnManager ccm = new ThreadSafeClientConnManager();

        // TODO: Make this configurable
        ccm.setMaxTotal( 20 );

        final SSLSocketFactory socketFactory = sslManager.newSSLSocketFactory();
        final SchemeRegistry registry = ccm.getSchemeRegistry();
        registry.register( new Scheme( "https", 443, socketFactory ) );

        final AbstractHttpClient hc = new ContentEncodingHttpClient( ccm, new BasicHttpParams() );
        if ( configurator != null )
        {
            configurator.configure( hc );
        }

        client = hc;
    }

    public HttpClient getClient()
    {
        return client;
    }

    @PreDestroy
    public void closeConnection()
    {
        client.getConnectionManager()
              .closeExpiredConnections();

        client.getConnectionManager()
              .closeIdleConnections( 2, TimeUnit.SECONDS );
    }

}
