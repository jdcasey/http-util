package org.commonjava.util.http.client;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.protocol.HttpContext;
import org.commonjava.util.http.HTTPException;
import org.commonjava.util.http.ssl.SSLManager;
import org.commonjava.util.http.ssl.threadlocal.ThreadLocalCredentialsProvider;

@ApplicationScoped
public class HTTPClient
{

    public static final String AUTH_SCOPE_PARAM = "HTTP::authscope";

    private HttpClient client;

    @Inject
    private SSLManager sslManager;

    @Inject
    private ClientConfigurator configurator;

    @Inject
    private ThreadLocalCredentialsProvider credProvider;

    public HTTPClient()
    {
    }

    public HTTPClient( final SSLManager sslManager, final ClientConfigurator configurator )
        throws HTTPException
    {
        this.sslManager = sslManager;
        this.configurator = configurator;

        init();
    }

    @PostConstruct
    public void init()
        throws HTTPException
    {
        if ( configurator == null )
        {
            configurator = new DefaultClientConfigurator();
        }

        final AbstractHttpClient hc =
            new DefaultHttpClient( configurator.createConnectionManager( sslManager ), new BasicHttpParams() );

        configurator.configure( hc );
        hc.setCredentialsProvider( credProvider );

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

    public HttpResponse execute( final HttpUriRequest request )
        throws IOException, ClientProtocolException
    {
        return client.execute( request );
    }

    public HttpResponse execute( final HttpUriRequest request, final HttpContext context )
        throws IOException, ClientProtocolException
    {
        return client.execute( request, context );
    }

    public <T> T execute( final HttpUriRequest request, final ResponseHandler<? extends T> responseHandler )
        throws IOException, ClientProtocolException
    {
        return client.execute( request, responseHandler );
    }

    public <T> T execute( final HttpUriRequest request, final ResponseHandler<? extends T> responseHandler,
                          final HttpContext context )
        throws IOException, ClientProtocolException
    {
        return client.execute( request, responseHandler, context );
    }

    public void dispose( final HttpUriRequest request )
    {
        credProvider.clear();

        request.abort();

        closeConnection();
    }

    public void bind( final Map<AuthScope, Credentials> creds )
    {
        credProvider.bind( creds );
    }

    public void bind( final AuthScope scope, final Credentials creds )
    {
        credProvider.bind( scope, creds );
    }

}
