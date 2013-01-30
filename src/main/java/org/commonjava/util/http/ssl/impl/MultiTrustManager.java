package org.commonjava.util.http.ssl.impl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

public class MultiTrustManager
    implements X509TrustManager
{

    private final List<X509TrustManager> delegates;

    public MultiTrustManager( final X509TrustManager... delegates )
    {
        this.delegates = new ArrayList<X509TrustManager>( Arrays.asList( delegates ) );
    }

    @Override
    public void checkClientTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        for ( int i = 0; i < delegates.size(); i++ )
        {
            final X509TrustManager tm = delegates.get( i );

            try
            {
                tm.checkClientTrusted( chain, authType );
            }
            catch ( final CertificateException e )
            {
                if ( i + 1 >= delegates.size() )
                {
                    throw e;
                }
            }
        }
    }

    @Override
    public void checkServerTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        for ( int i = 0; i < delegates.size(); i++ )
        {
            final X509TrustManager tm = delegates.get( i );

            try
            {
                tm.checkServerTrusted( chain, authType );
            }
            catch ( final CertificateException e )
            {
                if ( i + 1 >= delegates.size() )
                {
                    throw e;
                }
            }
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        final Set<X509Certificate> accepted = new LinkedHashSet<X509Certificate>();
        for ( final X509TrustManager tm : delegates )
        {
            final X509Certificate[] certs = tm.getAcceptedIssuers();
            if ( certs != null )
            {
                accepted.addAll( Arrays.asList( certs ) );
            }
        }

        return accepted.toArray( new X509Certificate[] {} );
    }

}
